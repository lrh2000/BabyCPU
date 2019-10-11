#include <cstdio>
#include <cstdlib>

int main(int argc, char **argv)
{
  if (argc != 2) {
    printf("Usage: %s filename\n", argv[0]);
    return -1;
  }

  FILE *f1 = fopen(argv[1], "r");
  FILE *f2 = fopen("memory_data.txt", "w");
  if (!f1 || !f2) {
    puts("Failed to open file!\n");
    return -1;
  }

  int x[8];
  for (int j = 0;j < 128;++j)
  {
    for (int i = 0;i < 8;++i)
      if (fscanf(f1, "%2x", x + i) != 1)
        x[i] = 0xCC;
    for (int i = 7;i >= 0;--i)
      fprintf(f2, i ? "%02x" : "%02x\n", x[i]);
  }

  fclose(f1);
  fclose(f2);

  return 0;
}
