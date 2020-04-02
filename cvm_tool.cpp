// CRI ROFS decryptor v0.01 by roxfan (c) 2010

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rofs_crypt.h"
#include "iso_parser.h"
#include "cvm_parser.h"

#include <string>
#include <vector>
#include <map>

class CmdLineParams
{
  std::vector<std::string> order_args;
  std::map<std::string, std::string> switch_params;
public:
  CmdLineParams(int argc, char *argv[])
  {
    int i = 0;
    while ( i < argc)
    {
      if ( argv[i][0] == '-' )
      {
        if ( i+1 >= argc )
        {
          printf("%s: switch without parameter", argv[i]);
          return;
        }
        switch_params[argv[i]+1] = argv[i+1];
        i += 2;
      }
      else
      {
        order_args.push_back(argv[i]);
        i++;
      }
    }
  }
  int num_args() { return order_args.size(); };
  const std::string& arg(int i) { return order_args[i]; };
  bool switch_param(const std::string& sw, std::string *param)
  { 
    if ( switch_params.find(sw) != switch_params.end() )
    {
      if ( param != NULL )
        *param = switch_params[sw];
      return true;
    }
    return false;
  };
};

const size_t sectsize = 0x800;

int cvm_to_iso(const char *cvm_file, const char *iso_file, const char *hdr_file, const char *password, bool verbose)
{
  FILE *inf = fopen(cvm_file, "rb");
  if ( inf == NULL )
  {
    printf("Error opening '%s for reading\n", cvm_file);
    return 1;
  }
  printf("Input file: %s\n", cvm_file);
  CvmParser cvm(inf);
  if ( !cvm.parse_cvm(verbose) )
    return 1;
  
  bool has_key = false;
  unsigned char key[8];
  if ( cvm.is_encrypted() )
  {
    if ( password == NULL || strlen(password) == 0 )
    {
      printf("File is encrypted but no password was provided.\n");
      return 1;
    }
    CalcKeyFromString(password, key);
    if ( verbose )
    {
      printf("Password '%s', key: ", password);
      for ( int i=0; i < 8; i++ )
        printf("%02X", key[i]);
      printf("\n");
    }
    has_key = true;
  }
  
  int isoStartSector = cvm.get_cvmh().isoStartSector;
  int isoZoneSector  = cvm.get_zone().datalocISO.sector;

  Iso9660Parser i9(inf, isoStartSector, isoZoneSector, has_key ? key : NULL, 8, sectsize);
  
  if ( !i9.parseDirTree(false) )
    return 1;

  char buf[sectsize];
  FILE *outf;
  outf = fopen(iso_file, "wb");
  if ( outf == NULL )
  {
    printf("Error opening '%s' for writing\n", iso_file);
    return 1;
  }
  printf("Output file: %s\n", iso_file);

  uint64_t nsects = cvm.get_zone().datalocISO.length / sectsize;
  for ( int i = 0; i < nsects; i++ )
  {
    if ( !i9.read_sector(buf, i) )
      return 1;
    if ( fwrite(buf, sectsize, 1, outf) != 1 )
    {
      printf("Write error.\n");
      return 1;
    }
  }
  fclose(outf);
  if ( hdr_file != NULL )
  {
    outf = fopen(hdr_file, "wb");
    if ( outf == NULL )
    {
      printf("Error opening '%s' for writing\n", hdr_file);
      return 1;
    }
    printf("Header file: %s\n", hdr_file);
    fseek(inf, 0, SEEK_SET);
    for ( int i = 0; i < isoStartSector; i++ )
    {
      if ( fread(buf, sectsize, 1, inf) != 1 )
      {
        printf("Read error.\n");
        return 1;
      }
      if ( fwrite(buf, sectsize, 1, outf) != 1 )
      {
        printf("Write error.\n");
        return 1;
      }
    }
    fclose(outf);
  }
  fclose(inf);
  return 0;
}

int iso_to_cvm(const char *cvm_file, const char *iso_file, const char *hdr_file, const char *password, bool verbose)
{
  FILE *iso = fopen(iso_file, "rb");
  if ( iso == NULL )
  {
    printf("Error opening '%s for reading\n", iso_file);
    return 1;
  }
  printf("Input file: %s\n", iso_file);
  
  FILE *hdr = fopen(hdr_file, "rb");
  if ( hdr == NULL )
  {
    printf("Error opening '%s for reading\n", hdr_file);
    return 1;
  }
  printf("Header file: %s\n", hdr_file);
  CvmParser cvm(hdr);
  if ( !cvm.parse_cvm(false) )
    return 1;
  
  Iso9660Parser i9(iso, 0, 0, NULL, 0, sectsize);
  if ( !i9.parseDirTree(false) )
    return 1;
  
  bool has_key = false;
  unsigned char key[8];
  if ( password != NULL && strlen(password) > 0 )
  {
    printf("Writing encrypted volume\n");
    CalcKeyFromString(password, key);
    if ( verbose )
    {
      printf("Password '%s', key: ", password);
      for ( int i=0; i < 8; i++ )
        printf("%02X", key[i]);
      printf("\n");
    }
    has_key = true;
  }
  else
  {
    printf("Writing unencrypted volume\n");
  }
  
  int isoStartSector = cvm.get_cvmh().isoStartSector;
  int isoZoneSector  = cvm.get_zone().datalocISO.sector;

  char buf[sectsize];
  FILE *outf;
  outf = fopen(cvm_file, "wb");
  if ( outf == NULL )
  {
    printf("Error opening '%s' for writing\n", cvm_file);
    return 1;
  }
  printf("Output file: %s\n", cvm_file);

  _fseeki64(iso, 0, SEEK_END);
  __int64 iso_length = _ftelli64(iso);
  cvm.set_iso_params(iso_length, has_key, verbose);
  cvm.write_cvm_headers(outf);

  // set key so the TOC sectors will be automatically encrypted on read
  if ( has_key )
    i9.set_key(key, 8);

  _fseeki64(outf, sectsize * cvm.get_zone().datalocISO.sector, SEEK_SET);
  uint64_t nsects = cvm.get_zone().datalocISO.length / sectsize;
  for ( int i = 0; i < nsects; i++ )
  {
    if ( !i9.read_sector(buf, i) )
      return 1;
    if ( fwrite(buf, sectsize, 1, outf) != 1 )
    {
      printf("Write error.\n");
      return 1;
    }
  }
  fclose(outf);
  fclose(iso);
  fclose(hdr);
  return 0;
}

int cvm_info(const char *cvm_file, const char *password, bool verbose)
{
  FILE *inf = fopen(cvm_file, "rb");
  if ( inf == NULL )
  {
    printf("Error opening '%s for reading\n", cvm_file);
    return 1;
  }
  printf("Input file: %s\n", cvm_file);
  CvmParser cvm(inf);
  if ( !cvm.parse_cvm(true) )
    return 1;
  
  bool has_key = false;
  unsigned char key[8];
  if ( cvm.is_encrypted() )
  {
    if ( password == NULL || strlen(password) == 0 )
    {
      printf("File is encrypted but no password was provided.\n");
      return 1;
    }
    CalcKeyFromString(password, key);
    if ( verbose )
    {
      printf("Password '%s', key: ", password);
      for ( int i=0; i < 8; i++ )
        printf("%02X", key[i]);
      printf("\n");
    }
    has_key = true;
  }
  
  int isoStartSector = cvm.get_cvmh().isoStartSector;
  int isoZoneSector  = cvm.get_zone().datalocISO.sector;

  Iso9660Parser i9(inf, isoStartSector, isoZoneSector, has_key ? key : NULL, 8, sectsize);
  
  if ( !i9.parseDirTree(true) )
    return 1;

  fclose(inf);
  return 0;
}

void usage()
{
  printf("ROFS tool v0.02 by roxfan (c) 2010.\n");
  printf("Usage: cvm_tool [options] <command> <file1>...\n");
  printf("    available commands:\n");
  printf("    info  [-p <password>] <file.cvm>                          Show information about a ROFS volume\n");
  printf("    split [-p <password>] <file.cvm> <file.iso> [<file.hdr>]  Extract ISO file from a ROFS volume\n");
  printf("    mkcvm [-p <password>] <file.cvm> <file.iso>  <file.hdr>   Make a ROFS volume from an ISO file and header file\n");
  //printf("    decrypt -p <password> <file1.cvm> <file2.cvm>             Decrypt a ROFS volume\n");
  //printf("    encrypt -p <password> <file1.cvm> <file2.cvm>             Encrypt a ROFS volume\n");
  exit(0);
}

int main(int argc, char *argv[])
{
  CmdLineParams opts(argc, argv);
  if ( opts.num_args() < 3 )
    usage();
  std::string command = opts.arg(1);
  std::string password;
  bool has_pw = opts.switch_param("p", &password);
  if ( command == "info" )
  {
    if ( opts.num_args() < 3 )
      usage();
    const char *cvm_file = opts.arg(2).c_str();
    return cvm_info(cvm_file, password.c_str(), true);
  }
  else if ( command == "split" )
  {
    if ( opts.num_args() < 4 )
      usage();
    const char *cvm_file = opts.arg(2).c_str();
    const char *iso_file = opts.arg(3).c_str();
    const char *hdr_file = NULL;
    if ( opts.num_args() > 4 )
      hdr_file = opts.arg(4).c_str();
    return cvm_to_iso(cvm_file, iso_file, hdr_file, password.c_str(), true);
  }
  else if ( command == "mkcvm" )
  {
    if ( opts.num_args() < 5 )
      usage();
    const char *cvm_file = opts.arg(2).c_str();
    const char *iso_file = opts.arg(3).c_str();
    const char *hdr_file = opts.arg(4).c_str();
    return iso_to_cvm(cvm_file, iso_file, hdr_file, password.c_str(), true);
  }
  else
  {
    usage();
  }
  /*
  FILE *inf = fopen(argv[1], "rb");
  if ( inf == NULL )
  {
    printf("Error opening '%s'\n", argv[1]);
    return 1;
  }
  printf("Input file: %s\n", argv[1]);
  CvmParser cvm(inf);
  if ( !cvm.parse_cvm(true) )
    return 1;
  if ( argc < 3 )
    return 0;
  unsigned char key[8];
  CalcKeyFromString(argv[2], key);
  printf("Password '%s', key: ", argv[2]);
  for ( int i=0; i < 8; i++ )
    printf("%02X", key[i]);
  printf("\n");
  
  int isoStartSector = cvm.get_cvmh().isoStartSector;
  int isoZoneSector  = cvm.get_zone().datalocISO.sector;
  const size_t sectsize = 0x800;
  Iso9660Parser i9(inf, isoStartSector, isoZoneSector, cvm.is_encrypted() ? key : NULL, 8, sectsize);
  if ( !i9.parseDirTree() )
    return 1;

  if ( argc < 4 )
    return 0;

  char buf[sectsize];
  int end_dirs = i9.get_end_dirs();
  if ( argc > 3 )
  {
    FILE *outf;
    outf = fopen(argv[3],"wb");
    if ( inf == NULL )
    {
      printf("Error opening '%s' for writing\n", argv[3]);
      return 1;
    }
    printf("Output file: %s\n", argv[3]);

    uint64_t nsects = cvm.get_zone().datalocISO.length / sectsize;
    for ( int i = 0; i < nsects; i++ )
    {
      if ( !i9.read_sector(buf, i) )
        return 1;
      if ( fwrite(buf, sectsize, 1, outf) != 1 )
      {
        printf("Write error.\n");
        return 1;
      }
    }
    fclose(outf);
  }
  fclose(inf);*/
}
