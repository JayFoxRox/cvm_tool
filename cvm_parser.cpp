#include "cvm_parser.h"
#include <stdlib.h>

inline uint32_t getBE32(void* buf) { return _byteswap_ulong(*(uint32_t*)(buf)); };
inline uint64_t getBE64(void* buf) { return _byteswap_uint64(*(uint64_t*)(buf)); };
inline void swap32(uint32_t* v) { *v = _byteswap_ulong(*v); };
inline void swap64(uint64_t* v) { *v = _byteswap_uint64(*v); };

#pragma pack(push, 1)
struct ChunkHeader
{
  uint32_t id;
  uint64_t len;
};
#pragma pack(pop)

bool swap_header(struct ChunkHeader* hdr)
{
  swap32(&hdr->id);
  swap64(&hdr->len);
  return true;
}

bool parseChunkHeader(FILE *inf, ChunkHeader *hdr)
{
  if ( fread(hdr, sizeof(ChunkHeader), 1, inf) != 1 )
  {
    printf("parseChunkHeader: read error\n");
    return false;
  }
  return swap_header(hdr);
}

bool swap_cvmh(struct CvmhInfo* cvmh, bool toNative)
{
  int numEntries;
  swap64(&cvmh->fileSize);
  swap32(&cvmh->flags_30);
  swap32(&cvmh->fsId);
  if ( !toNative )
    numEntries = cvmh->numEntries;
  swap32(&cvmh->numEntries);
  if ( toNative )
    numEntries = cvmh->numEntries;
  swap32(&cvmh->tocIndex);
  swap32(&cvmh->isoStartSector);
  if ( numEntries >= (0x800-0x100)/4 )
  {
    printf("bad numEntries!\n");
    return false;
  }  
  for ( int i = 0; i < numEntries; i++ )
    swap32(&cvmh->sectorTable[i]);
  return true;
}

bool swap_zone(struct ZoneInfo *zone)
{
  swap32(&zone->dw_Zone0C);
  swap32(&zone->sectorLen1);
  swap32(&zone->sectorLen2);
  swap32(&zone->dataloc1.sector);
  swap64(&zone->dataloc1.length);
  swap32(&zone->datalocISO.sector);
  swap64(&zone->datalocISO.length);
  return true;
}

const char *fourcc2str(uint32_t fourcc)
{
  static char txt[5];
  *(uint32_t*)txt = _byteswap_ulong(fourcc);
  txt[4] = 0;
  return txt;
}

void print_cvmh(const CvmhInfo &cvmh)
{
  printf("CVMH chunk:\n");
  printf("  file size: 0x%08I64X\n", cvmh.fileSize);
  printf("  date: %04d-%02d-%02d %02d:%02d:%02d, GMT offset: %d minutes\n",
    cvmh.date.year + 1900, cvmh.date.month, cvmh.date.day,
    cvmh.date.hour, cvmh.date.minute, cvmh.date.second, cvmh.date.gmt_offset*15);
  printf("  verinfo1: %d.%d.%d.%d\n", cvmh.verinfo1[0], cvmh.verinfo1[1], cvmh.verinfo1[2], cvmh.verinfo1[3]);
  printf("  flags_30: 0x%08X\n", cvmh.flags_30);
  if ( cvmh.flags_30 & 0x10 )
    printf("    (encrypted TOC)\n");
  if ( (cvmh.flags_30 & ~0x10) != 0 )
    printf("    (unknown flags present!)\n");
  printf("  FS id: %s\n", fourcc2str(cvmh.fsId));
  printf("  maker id: '%s'\n", cvmh.makerId);
  printf("  verinfo2: %d.%d.%d.%d\n", cvmh.verinfo2[0], cvmh.verinfo2[1], cvmh.verinfo2[2], cvmh.verinfo2[3]);
  printf("  flag_7C: %d\n", cvmh.flag_7C);
  printf("  flag_7D: %d\n", cvmh.flag_7D);
  printf("  zone table (%d entries): [", cvmh.numEntries);
  for ( int i = 0; i < cvmh.numEntries; i++ )
    printf(" %d", cvmh.sectorTable[i]);
  printf(" ]\n");
  printf("  zone TOC sector: %d (index %d)\n", cvmh.sectorTable[cvmh.tocIndex], cvmh.tocIndex);
  printf("  ISO start sector: %d\n", cvmh.isoStartSector);
}

void print_zone(const ZoneInfo &zone)
{
  printf("ZONE chunk:\n");
  printf("  zone0C: %d\n", zone.dw_Zone0C);
  printf("  zone10: %d\n", zone.b_Zone10);
  printf("  zone11: %d\n", zone.b_Zone11);
  printf("  zone12: %d\n", zone.b_Zone12);
  printf("  zone13: %d\n", zone.b_Zone13);
  printf("  zone14: %d\n", zone.b_Zone14);
  printf("  sector len 1: %d\n", zone.sectorLen1);
  printf("  sector len 2: %d\n", zone.sectorLen2);
  printf("  dataloc1: sector %d, len 0x%08I64X\n", zone.dataloc1.sector, zone.dataloc1.length);
  printf("  dataloc ISO: sector %d, len 0x%08I64X\n", zone.datalocISO.sector, zone.datalocISO.length);
}

bool CvmParser::parse_cvmh(bool verbose)
{
  if ( fread(&cvmh, sizeof(cvmh), 1, inf) != 1 )
  {
    printf("read error\n");
    return false;
  }
  if ( !swap_cvmh(&cvmh, true) )
  {
    printf("bad cvmh header\n");
    return false;
  }
  if ( verbose )
    print_cvmh(cvmh);
  return true;
}

bool CvmParser::parse_zone(bool verbose)
{
  if ( fread(&zone, sizeof(zone), 1, inf) != 1 )
  {
    printf("parse_zone: read error\n");
    return false;
  }
  if ( !swap_zone(&zone) )
  {
    printf("parse_zone: bad zone header\n");
    return false;
  }
  if ( verbose )
    print_zone(zone);
  data1chunk = malloc(zone.dataloc1.length);
  _fseeki64(inf, 0x800 * zone.dataloc1.sector, SEEK_SET);
  if ( fread(data1chunk, zone.dataloc1.length, 1, inf) != 1 )
  {
    printf("parse_zone: read error\n");
    return false;
  }
  return true;
}

bool CvmParser::parse_cvm(bool verbose)
{
  ChunkHeader hdr;
  __int64 off = 0;
  _fseeki64(inf, 0, SEEK_END);
  __int64 fsize = _ftelli64(inf);
  while ( off < fsize )
  {
    if ( verbose )
      printf("%08I64X: ", off);
    _fseeki64(inf, off, SEEK_SET);
    if ( !parseChunkHeader(inf, &hdr) )
      return false;
    if ( verbose )
      printf("chunk '%s', length 0x%08I64X (0x%08I64X)\n", fourcc2str(hdr.id), hdr.len, hdr.len+12);
    switch ( hdr.id )
    {
      case 'CVMH':
        if ( !parse_cvmh(verbose) )
          return false;
        break;
      case 'ZONE':
        if ( !parse_zone(verbose) )
          return false;
        break;
      default:
        printf("Unknown chunk type!\n");
        return false;
    }
    off += hdr.len + 12;
  }
  return true;
}

bool CvmParser::set_iso_params(uint64_t iso_length, bool encrypted, bool verbose)
{
  if ( verbose )
    printf("Patching ISO zone length to 0x%08I64X\n", iso_length);
  zone.datalocISO.length = iso_length;
  uint64_t file_length = iso_length + cvmh.isoStartSector * 0x800;
  if ( verbose )
    printf("Patching file size to 0x%08I64X\n", file_length);
  cvmh.fileSize = file_length;
  if ( verbose )
    printf("Setting encryption flag to %d\n", encrypted);
  if ( encrypted )
    cvmh.flags_30 |= 0x10;
  else
    cvmh.flags_30 &= ~0x10;
  return true;
}

bool writeChunkHeader(FILE *outf, ChunkHeader *hdr)
{
  if ( !swap_header(hdr) )
    return false;
  if ( fwrite(hdr, sizeof(ChunkHeader), 1, outf) != 1 )
  {
    printf("writeChunkHeader: write error\n");
    return false;
  }
  return true;
}

bool CvmParser::write_cvmh(FILE *outf)
{
  ChunkHeader hdr;
  hdr.id = 'CVMH';
  hdr.len = sizeof(cvmh);
  fseek(outf, 0, SEEK_SET);
  if ( !writeChunkHeader(outf, &hdr) )
  {
    printf("write_cvmh: write error\n");
    return false;
  }
  struct CvmhInfo cvmh1 = cvmh;
  if ( !swap_cvmh(&cvmh1, false) )
  {
    printf("write_cvmh: bad header\n");
    return false;
  }
  if ( fwrite(&cvmh1, sizeof(cvmh1), 1, outf) != 1 )
  {
    printf("write_cvmh: write error\n");
    return false;
  }
  return true;
}

bool CvmParser::write_zone(FILE *outf)
{
  ChunkHeader hdr;
  hdr.id = 'ZONE';
  hdr.len = zone.dataloc1.length + zone.datalocISO.length + sizeof(ZoneInfo);
  if ( !writeChunkHeader(outf, &hdr) )
  {
    printf("write_zone: write error\n");
    return false;
  }
  struct ZoneInfo zone1 = zone;
  if ( !swap_zone(&zone1) )
  {
    printf("write_zone: bad zone header\n");
    return false;
  }
  if ( fwrite(&zone1, sizeof(zone1), 1, outf) != 1 )
  {
    printf("write_zone: write error\n");
    return false;
  }
  _fseeki64(outf, 0x800 * zone.dataloc1.sector, SEEK_SET);
  if ( fwrite(data1chunk, zone.dataloc1.length, 1, outf) != 1 )
  {
    printf("write_zone: write error\n");
    return false;
  }
  return true;
}

bool CvmParser::write_cvm_headers(FILE *outf)
{
  return write_cvmh(outf) && !write_zone(outf);
}

CvmParser::~CvmParser()
{ 
  if ( data1chunk != NULL )
    free(data1chunk);
};