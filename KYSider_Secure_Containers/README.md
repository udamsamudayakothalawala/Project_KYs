# Project_KYs



The KYsider is program designed to compress files and folders in specific file format named as .kysd (kysider secured document)
and it follows LZ77, LZSS and Huffman container methods and encrypt content using AES-256-GCM and ChaCha20-poly1305.
- used languages : python

The created file secured with password and EncID. if password or EncID wrong or correct password and Wrong EncID, 
Empty EncID or correct encID with wrong password entered in three time. it trigger self shredding mechanism which can recovered only
with boundID only in KYSider program.
