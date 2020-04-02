#include <stdio.h>

class Iso9660Parser
{
  FILE *f;
  unsigned char *key;
  int keyLen;
  int sectorSize;
  int isoZoneSector;
  int isoStartSector;
  int end_dir_sect;

  int isoToLogical (int isosec) { return isosec + isoZoneSector - isoStartSector; };
  int isoToPhysical(int isosec) { return isosec + isoStartSector; };
  bool parseDir(int extent, int size, bool verbose);
  bool read_sectors_raw(void* buf, int isosec, int numsects, bool decrypt);
public:
  Iso9660Parser(FILE *_f, int _isoStartSector, int _isoZoneSector, unsigned char *_key, int _keyLen, int _sectorSize = 0x800):
   f(_f), isoStartSector(_isoStartSector), isoZoneSector(_isoZoneSector), key(_key), keyLen(_keyLen), sectorSize(_sectorSize),
   end_dir_sect(-1)
  {
  };
  bool parseDirTree(bool verbose);
  int get_end_dirs() { return end_dir_sect; };
  bool read_sector(void* buf, int isosec);
  void set_key(unsigned char *_key, int _keyLen) { key = _key; keyLen = _keyLen; };
};
