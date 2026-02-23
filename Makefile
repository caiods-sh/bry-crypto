PROJECT_DIR ?= /home/vboxuser/softwares/bry# Alterar para diretório que o projeto foi clonado
BUILD_DIR = $(PROJECT_DIR)/build/build/Release

DOC_DIR ?= $(PROJECT_DIR)/resources/arquivos/doc.txt
P12_FILE_DIR = $(PROJECT_DIR)/resources/pkcs12/cert_unit_test.pfx
P12_PASSWORD ?= devc++
P7S_FILE = $(PROJECT_DIR)/signature.p7s

.PHONY: setup build run_challenge_one run_challenge_two run_challenge_tree run_api run_tests clean

setup:
	conan install . --output-folder=build --build=missing
	cmake --preset conan-release

build: setup
	cmake --build --preset conan-release

build_docker_image:
	docker build -t bry-challenge .

run_docker_api:
	docker run -p 8080:8080 bry-challenge

run_challenge_one:
	$(BUILD_DIR)/src/bry_challenge_one $(DOC_DIR)

run_challenge_two:
	$(BUILD_DIR)/src/bry_challenge_two $(DOC_DIR) $(P12_FILE_DIR) $(P12_PASSWORD)

run_challenge_tree:
	$(BUILD_DIR)/src/bry_challenge_tree $(P7S_FILE)

run_api:
	$(BUILD_DIR)/src/bry_api

run_tests: build
	cd $(BUILD_DIR)/tests && ctest --output-on-failure

clean:
	rm -rf build/ CMakeUserPresets.json signature.p7s
