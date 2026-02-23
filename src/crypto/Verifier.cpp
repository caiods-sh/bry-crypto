#include "Verifier.hpp"
#include "Hash.hpp"
#include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <sstream>

namespace crypto {

// ─── Helper ──────────────────────────
static std::string asn1TimeToString(const ASN1_TIME* time) {
    if (!time) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";

    ASN1_TIME_print(bio, time);

    char buf[128] = {};
    BIO_read(bio, buf, sizeof(buf) - 1);
    BIO_free(bio);

    return std::string(buf);
}


VerificationResult Verifier::verifyP7s(const std::string& p7sFilePath) {
    VerificationResult result = {false, "", "", "", ""};

    BIO* in = BIO_new_file(p7sFilePath.c_str(), "rb");
    if (!in) throw std::runtime_error("Could not open signature file: " + p7sFilePath);

    CMS_ContentInfo* cms = d2i_CMS_bio(in, nullptr);
    BIO_free(in);
    if (!cms) throw std::runtime_error("Failed to parse CMS structure");

    BIO* outContent = BIO_new(BIO_s_mem());
    if (CMS_verify(cms, nullptr, nullptr, nullptr, outContent, CMS_NO_SIGNER_CERT_VERIFY) == 1) {
        result.isValid = true;
    }

    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms);
    if (sis && sk_CMS_SignerInfo_num(sis) > 0) {
        CMS_SignerInfo* si = sk_CMS_SignerInfo_value(sis, 0);

        X509_ALGOR* alg = nullptr;
        CMS_SignerInfo_get0_algs(si, nullptr, nullptr, &alg, nullptr);
        if (alg) {
            int algNid = OBJ_obj2nid(alg->algorithm);
            result.hashAlgorithm = OBJ_nid2sn(algNid);
        }

        STACK_OF(X509)* certs = CMS_get0_signers(cms);
        if (certs && sk_X509_num(certs) > 0) {
            X509* signerCert = sk_X509_value(certs, 0);
            X509_NAME* subject = X509_get_subject_name(signerCert);

            char cnBuf[256] = {};
            X509_NAME_get_text_by_NID(subject, NID_commonName, cnBuf, sizeof(cnBuf));
            result.signerCommonName = cnBuf;
        }

        int idx = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1);
        if (idx >= 0) {
            X509_ATTRIBUTE* attr = CMS_signed_get_attr(si, idx);
            if (attr) {
                ASN1_TYPE* attrVal = X509_ATTRIBUTE_get0_type(attr, 0);
                if (attrVal) {
                    const ASN1_TIME* signingTime = nullptr;
                    if (attrVal->type == V_ASN1_UTCTIME)
                        signingTime = attrVal->value.utctime;
                    else if (attrVal->type == V_ASN1_GENERALIZEDTIME)
                        signingTime = attrVal->value.generalizedtime;

                    if (signingTime)
                        result.signingTime = asn1TimeToString(signingTime);
                }
            }
        }
    }

    BUF_MEM* bufMem = nullptr;
    BIO_get_mem_ptr(outContent, &bufMem);
    if (bufMem && bufMem->data && bufMem->length > 0) {
        result.hashHex = Hash::GenerateSHA512FromBuffer(
            reinterpret_cast<const unsigned char*>(bufMem->data), 
            bufMem->length
        );
    }

    BIO_free(outContent);
    CMS_ContentInfo_free(cms);

    return result;
}

}