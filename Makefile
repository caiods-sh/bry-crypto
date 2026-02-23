DOC_DIR=/home/vboxuser/softwares/bry/resources/arquivos/doc.txt
P12_FILE_DIR=/home/vboxuser/softwares/bry/resources/pkcs12/cert_unit_test.pfx
# P12_PASSWORD=bry123456
P12_PASSWORD=devc++

P7S_FILE=/home/vboxuser/softwares/bry/signature.p7s

.PHONY: setup build run_challenge_one run_tests clean

setup:
	conan install . --output-folder=build --build=missing
	cmake --preset conan-release

build: setup
	cmake --build --preset conan-release

run_challenge_one:
	./build/build/Release/src/bry_challenge_one $(DOC_DIR)

run_challenge_two:
	./build/build/Release/src/bry_challenge_two $(DOC_DIR) $(P12_FILE_DIR) $(P12_PASSWORD)

run_challenge_tree:
	./build/build/Release/src/bry_challenge_tree $(P7S_FILE)

run_api:
	./build/build/Release/src/bry_api

run_tests: build
	cd ./build/build/Release/tests && ctest --output-on-failure

clean:
	rm -rf build/ CMakeUserPresets.json signature.p7s