DOC_DIR=/home/vboxuser/softwares/bry/resources/arquivos/doc.txt

.PHONY: setup compile run_challenge_one clean


setup:
	conan install . --output-folder=build --build=missing
	cmake --preset conan-release

compile:
	cmake --build --preset conan-release

run_challenge_one:
	./build/build/Release/src/bry_challenge_one $(DOC_DIR)


run_tests: compile
	cd ./build/build/Release/tests && ctest --output-on-failure

clean:
	rm -rf build/ CMakeUserPresets.json