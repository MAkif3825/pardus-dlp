#include "extensions.h"
#include "../utils/file_utils.h"
#include <stdio.h>
#include <string.h>

int
extension_db_init(const char *db_path, struct bpf_map *ext_map)
{
	FILE *file = fopen(db_path, "r");
	if (!file)
		return -1;

	char line[256];
	int loaded_count = 0;

	while (fgets(line, sizeof(line), file)) {
		trim_whitespace(line);

		if (line[0] == '#' || line[0] == '\0')
			continue;

		if (strlen(line) >= 8)
			continue;

		char key[8] = { 0 };
		strncpy(key, line, sizeof(key) - 1);

		unsigned int value = 1;

		if (bpf_map__update_elem(ext_map, &key, sizeof(key), &value,
					 sizeof(value), BPF_ANY)
		    == 0) {
			loaded_count++;
		}
	}

	fclose(file);
	return loaded_count;
}