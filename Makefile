ifeq ($(OS), Windows_NT)
	EXTRA_TEST_FLAGS :=
else
	EXTRA_TEST_FLAGS := -fsanitize=address -fsanitize=undefined -fstack-protector-all
endif

all:
	@gcc -std=c99 -Wall -Wextra -Werror $(EXTRA_TEST_FLAGS) -Isrc src/sha256.c test/test.c -o test/run_tests
	@test/run_tests
