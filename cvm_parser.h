#include <stdio.h>

/*
CVMH header
0000000000: 43 56 4D 48 00 00 00 00 ¦ 00 00 07 F4 00 00 00 00  CVMH      •ô
0000000010: 00 00 00 00 00 00 00 00 ¦ 00 00 00 00 00 00 00 00
0000000020: 00 F1 70 00 68 08 06 0E ¦ 00 00 24 00 01 01 00 00   ñp h•¦d  $ OO
0000000030: 00 00 00 10 52 4F 46 53 ¦ 52 4F 46 53 42 4C 44 20     >ROFSROFSBLD
0000000040: 56 65 72 2E 31 2E 35 32 ¦ 20 32 30 30 33 2D 30 36  Ver.1.52 2003-06
0000000050: 2D 30 39 00 00 00 00 00 ¦ 00 00 00 00 00 00 00 00  -09
0000000060: 00 00 00 00 00 00 00 00 ¦ 00 00 00 00 00 00 00 00
0000000070: 00 00 00 00 00 00 00 00 ¦ 01 1F 00 00 01 00 00 00          O¡  O
0000000080: 00 00 00 01 00 00 00 00 ¦ 00 00 00 03 00 00 00 00     O       ¦

00:  4 bytes  'CVMH' tag name
04:  int64be  block length (without header)
0C: 16 bytes  unused (zeroes)
1C:  int64be  total CVM size
24:  7 bytes  time and date info (iso9660 9.1.5 format)
      year (1900-based)
      month
      day
      hour
      minute
      second
      GTM offset in 15-minute units (-48 to +52)
2B:  1 byte   padding?
2C:  4 bytes  version info?
30:  int32be  flags (0x10 = encrypted TOC)
34:  4 bytes  'ROFS' magic
38: 64 bytes  make tool id string
78:  4 bytes  version info?
7C:  1 byte   unknown flag
7D:  1 byte   unknown flag
7E:  2 bytes  padding?
80:  int32be  number of entries in the sector table
84:  int32be  index of the zone info sector
88:  int32be  start sector of the ISO image
8C: 116 bytes unused
100: numEntries*4  table of sector numbers
*/

typedef unsigned char uint8_t;
typedef char int8_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;

#pragma pack(push, 1)
struct iso_datetime
{
  uint8_t year;
  uint8_t month;
  uint8_t day;
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
  int8_t  gmt_offset;
};

struct CvmhInfo
{
  char _padding0[16];
  uint64_t fileSize;
  iso_datetime date;
  char _padding1;
  char verinfo1[4];
  uint32_t flags_30;
  uint32_t fsId;
  char makerId[64];
  char verinfo2[4];
  char flag_7C;
  char flag_7D;
  char _padding2[2];
  uint32_t numEntries;
  uint32_t tocIndex;
  uint32_t isoStartSector;
  char _padding3[0x100-0x8C];
  uint32_t sectorTable[(0x800-0x100)/4];
};

struct ZoneDataLoc
{
  uint32_t sector;
  uint64_t length;
};

struct ZoneInfo
{
  uint32_t dw_Zone0C;
  char b_Zone10;
  char b_Zone11;
  char b_Zone12;
  char b_Zone13;
  char b_Zone14;
  char padding1[3];
  uint32_t sectorLen1;
  uint32_t sectorLen2;
  ZoneDataLoc dataloc1;
  ZoneDataLoc datalocISO;
  char padding2[0x800-0x38];
};
#pragma pack(pop)

class CvmParser
{
  FILE *inf;
  struct CvmhInfo cvmh;
  struct ZoneInfo zone;
  void *data1chunk;
  bool parse_cvmh(bool verbose = false);
  bool parse_zone(bool verbose = false);
  bool write_zone(FILE *outf);
  bool write_cvmh(FILE *outf);
public:
  CvmParser(FILE *f): inf(f), data1chunk(NULL) {};
  ~CvmParser();
  bool parse_cvm(bool verbose = false);
  bool print_info();
  const struct CvmhInfo& get_cvmh() { return cvmh; };
  const struct ZoneInfo& get_zone() { return zone; };
  bool is_encrypted() { return (cvmh.flags_30 & 0x10) != 0; };
  bool set_iso_params(uint64_t iso_length, bool encrypted, bool verbose = false);
  bool write_cvm_headers(FILE *outf);
};
