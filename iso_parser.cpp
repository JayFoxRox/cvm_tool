#include "iso9660.h"
#include "rofs_crypt.h"
#include "iso_parser.h"
#include <malloc.h>
#include <memory.h>

int  isonum_711(char * p);
int  isonum_731(char * p);
int  isonum_721(char * p);
int  isonum_723(char * p);
int  isonum_733(char * p);

int isonum_711(char *p)
{
  return (*p & 0xff);
}

int isonum_731(char *p)
{
  return ((p[0] & 0xff)
          | ((p[1] & 0xff) << 8)
          | ((p[2] & 0xff) << 16)
          | ((p[3] & 0xff) << 24));
}

int isonum_721(char *p)
{
  return ((p[0] & 0xff) | ((p[1] & 0xff) << 8));
}

int isonum_723 (char *p)
{
  return (isonum_721 (p));
}

int isonum_733 (char *p)
{
   return (isonum_731 ((char *)p));
}

bool Iso9660Parser::read_sectors_raw(void* buf, int isosec, int numsects, bool decrypt)
{
  fseek(f, isoToPhysical(isosec)*sectorSize, SEEK_SET);
  if ( fread(buf, sectorSize, numsects, f) != numsects )
  {
    printf("read error for sector %d\n", isoToPhysical(isosec));
    return false;
  }
  if ( decrypt && key != NULL )
    DecryptSectors(buf, isoToLogical(isosec), numsects, sectorSize, key, keyLen);
  return true;
}

bool Iso9660Parser::parseDir(int dir_sect, int dir_size, bool verbose)
{
  char *buf = (char*) _alloca(sectorSize);
  struct iso_directory_record * idr;
  
  if ( verbose )
    printf("Parsing directory in sector %d, size 0x%X\n", dir_sect, dir_size);

  while ( dir_size > 0 )
  {
    if ( !read_sectors_raw(buf, dir_sect++, 1, true) )
      return false;
    
    int dirchunk = sectorSize;
    if ( dirchunk > dir_size )
      dirchunk = dir_size;
    dir_size -= dirchunk;

    idr = (struct iso_directory_record *)buf;    
    while ( dirchunk > 0 )
    {
      int rec_len = idr->length[0];
      if ( rec_len == 0 )
        break;
      if ( rec_len < 0x22 )
      {
        printf("Bad entry size: 0x%X\n", rec_len);
        return false;
      }
      int nlen  = isonum_711(idr->name_len);
      int flags = isonum_711(idr->flags);
      int extent  = isonum_733(idr->extent);
      int size  = isonum_733(idr->size);
      int extattrlen = isonum_711(idr->ext_attr_length);
      if ( verbose )
        printf("  entry flags 0x%02X, extent %d (extattr %d), size 0x%X, name '%*s'\n", flags, extent, extattrlen, size, nlen, idr->name);
      if ( flags & ISO_DIRECTORY )
      {
        if ( nlen != 1 || idr->name[0] != 0 && idr->name[0] != 1 ) // ignore . and .. entries
        {
          if ( !parseDir(extent + extattrlen, size, verbose) )
            return false;
        }
      }
      dirchunk -= rec_len;
      idr = (struct iso_directory_record *)((char*)idr + rec_len);
    }
  }
  if ( end_dir_sect < dir_sect )
    end_dir_sect = dir_sect;
  return true;
}

// PVD is in sector 16
const int pvd_sec = 16;

bool Iso9660Parser::parseDirTree(bool verbose)
{
  struct iso_primary_descriptor ipd;
  struct iso_directory_record * idr;
  int max_sec = pvd_sec;
  if ( !read_sectors_raw(&ipd, pvd_sec, 1, true) )
    return false;
  
  if ( isonum_711(ipd.type) != ISO_VD_PRIMARY || memcmp(ipd.id, ISO_STANDARD_ID, 5) != 0 )
  {
    printf("Bad PVD header (%s); bad decryption key?\n", ipd.id);
    return false;
  }
  int blocksize = isonum_723(ipd.logical_block_size);
  if ( blocksize != sectorSize )
  {
    printf("Bad block size: %d (expected %d)\n", blocksize, sectorSize);
    return false;
  }
  idr = (struct iso_directory_record *)&ipd.root_directory_record;
  end_dir_sect = 0;
  int rootdir_sect = isonum_733(idr->extent) + isonum_711(idr->ext_attr_length);
  int rootdir_size = isonum_733(idr->size);
  if ( !parseDir(rootdir_sect, rootdir_size, verbose) )
    return false;
  if ( verbose )
    printf("Successfully parsed directory tree, end toc sector: %d (phys offset 0x%X)\n", end_dir_sect, isoToPhysical(end_dir_sect)*sectorSize);
  return true;
}

bool Iso9660Parser::read_sector(void* buf, int isosec)
{
  if ( end_dir_sect < 0 )
    return false;
  return read_sectors_raw(buf, isosec, 1, (isosec >= pvd_sec && isosec < end_dir_sect) );
}
