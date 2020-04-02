void DecryptSectors(void *buf, int startSec, int nSecs, int secSize, unsigned char *key, int keyLen);
int CalcKeyFromString(const char *password, unsigned char *key);
