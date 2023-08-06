#include "DNSServer.h"
#include <lwip/def.h>
#include <Arduino.h>


DNSServer::DNSServer()
{
  _ttl = htonl(60);
  _errorReplyCode = DNSReplyCode::NonExistentDomain;
}

bool DNSServer::start(const uint16_t &port, const String &domainName /* of the ESP32 AP itself*/,
                     const IPAddress &resolvedIP /*the ip of the ESP32 AP itself*/,
                     const String &domainName1, const IPAddress &resolvedIP1 /* another domain and ip */,
                     const String &domainName2, const IPAddress &resolvedIP2 /* another domain and ip */,
                     const String &domainName3, const IPAddress &resolvedIP3 /* another domain and ip */,
                     const String &domainName4, const IPAddress &resolvedIP4 /* another domain and ip */)
{
  _port = port;
  _buffer = NULL;
  _domainName = domainName;
  _domainName1 = domainName1;
  _domainName2 = domainName2;
  _domainName3 = domainName3;
  _domainName4 = domainName4;
  
  _resolvedIP[0] = resolvedIP[0];
  _resolvedIP[1] = resolvedIP[1];
  _resolvedIP[2] = resolvedIP[2];
  _resolvedIP[3] = resolvedIP[3];

  _resolvedIP1[0] = resolvedIP1[0];
  _resolvedIP1[1] = resolvedIP1[1];
  _resolvedIP1[2] = resolvedIP1[2];
  _resolvedIP1[3] = resolvedIP1[3];

  _resolvedIP2[0] = resolvedIP2[0];
  _resolvedIP2[1] = resolvedIP2[1];
  _resolvedIP2[2] = resolvedIP2[2];
  _resolvedIP2[3] = resolvedIP2[3];

  _resolvedIP3[0] = resolvedIP3[0];
  _resolvedIP3[1] = resolvedIP3[1];
  _resolvedIP3[2] = resolvedIP3[2];
  _resolvedIP3[3] = resolvedIP3[3];

  _resolvedIP4[0] = resolvedIP4[0];
  _resolvedIP4[1] = resolvedIP4[1];
  _resolvedIP4[2] = resolvedIP4[2];
  _resolvedIP4[3] = resolvedIP4[3];

  
  downcaseAndRemoveWwwPrefix(_domainName);
  return _udp.begin(_port) == 1;
}

void DNSServer::setErrorReplyCode(const DNSReplyCode &replyCode)
{
  _errorReplyCode = replyCode;
}

void DNSServer::setTTL(const uint32_t &ttl)
{
  _ttl = htonl(ttl);
}

void DNSServer::stop()
{
  _udp.stop();
  free(_buffer);
  _buffer = NULL;
}

void DNSServer::downcaseAndRemoveWwwPrefix(String &domainName)
{
  domainName.toLowerCase();
  domainName.replace("www.", "");
}

void DNSServer::processNextRequest()
{
  _currentPacketSize = _udp.parsePacket();
  if (_currentPacketSize)
  {
    if (_buffer != NULL) free(_buffer);
    _buffer = (unsigned char*)malloc(_currentPacketSize * sizeof(char));
    if (_buffer == NULL) return;
    _udp.read(_buffer, _currentPacketSize);
    _dnsHeader = (DNSHeader*) _buffer;

    if (_dnsHeader->QR == DNS_QR_QUERY &&
        _dnsHeader->OPCode == DNS_OPCODE_QUERY &&
        requestIncludesOnlyOneQuestion()
       )
    {
      String req_domain = getDomainNameWithoutWwwPrefix();
      if (req_domain == _domainName)
      {
         replyWithIP(0);
      }
      else if (req_domain == _domainName1)
      {
         replyWithIP(1);
      }
      else if (req_domain == _domainName2)
      {
         replyWithIP(2);
      }
      else if (req_domain == _domainName3)
      {
         replyWithIP(3);
      }
      else if (req_domain == _domainName4)
      {
         replyWithIP(4);
      }
    }
    else if (_dnsHeader->QR == DNS_QR_QUERY)
    {
      replyWithCustomCode();
    }

    free(_buffer);
    _buffer = NULL;
  }
}

bool DNSServer::requestIncludesOnlyOneQuestion()
{
  return ntohs(_dnsHeader->QDCount) == 1 &&
         _dnsHeader->ANCount == 0 &&
         _dnsHeader->NSCount == 0 &&
         _dnsHeader->ARCount == 0;
}

String DNSServer::getDomainNameWithoutWwwPrefix()
{
  String parsedDomainName = "";
  if (_buffer == NULL) return parsedDomainName;
  unsigned char *start = _buffer + 12;
  if (*start == 0)
  {
    return parsedDomainName;
  }
  int pos = 0;
  while(true)
  {
    unsigned char labelLength = *(start + pos);
    for(int i = 0; i < labelLength; i++)
    {
      pos++;
      parsedDomainName += (char)*(start + pos);
    }
    pos++;
    if (*(start + pos) == 0)
    {
      downcaseAndRemoveWwwPrefix(parsedDomainName);
      return parsedDomainName;
    }
    else
    {
      parsedDomainName += ".";
    }
  }
}

void DNSServer::replyWithIP(uint8_t index)
{
  if (_buffer == NULL) return;
  _dnsHeader->QR = DNS_QR_RESPONSE;
  _dnsHeader->ANCount = _dnsHeader->QDCount;
  _dnsHeader->QDCount = _dnsHeader->QDCount; 
  //_dnsHeader->RA = 1;  

  _udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
  _udp.write(_buffer, _currentPacketSize);

  _udp.write((uint8_t)192); //  answer name is a pointer
  _udp.write((uint8_t)12);  // pointer to offset at 0x00c

  _udp.write((uint8_t)0);   // 0x0001  answer is type A query (host address)
  _udp.write((uint8_t)1);

  _udp.write((uint8_t)0);   //0x0001 answer is class IN (internet address)
  _udp.write((uint8_t)1);
 
  _udp.write((unsigned char*)&_ttl, 4);

  // Length of RData is 4 bytes (because, in this case, RData is IPv4)
  _udp.write((uint8_t)0);
  _udp.write((uint8_t)4);
  if (index == 0)
  {
     _udp.write(_resolvedIP, sizeof(_resolvedIP));
  }
  else if (index == 1)
  {
     _udp.write(_resolvedIP1, sizeof(_resolvedIP1));
  }
  else if (index == 2)
  {
     _udp.write(_resolvedIP2, sizeof(_resolvedIP2));
  }
  else if (index == 3)
  {
     _udp.write(_resolvedIP3, sizeof(_resolvedIP3));
  }
  else if (index == 4)
  {
     _udp.write(_resolvedIP4, sizeof(_resolvedIP4));
  }
  _udp.endPacket();



  #ifdef DEBUG
    DEBUG_OUTPUT.print("DNS responds: ");
    DEBUG_OUTPUT.print(_resolvedIP[0]);
    DEBUG_OUTPUT.print(".");
    DEBUG_OUTPUT.print(_resolvedIP[1]);
    DEBUG_OUTPUT.print(".");
    DEBUG_OUTPUT.print(_resolvedIP[2]);
    DEBUG_OUTPUT.print(".");
    DEBUG_OUTPUT.print(_resolvedIP[3]);
    DEBUG_OUTPUT.print(" for ");
    DEBUG_OUTPUT.println(getDomainNameWithoutWwwPrefix());
  #endif
}

void DNSServer::replyWithCustomCode()
{
  if (_buffer == NULL) return;
  _dnsHeader->QR = DNS_QR_RESPONSE;
  _dnsHeader->RCode = (unsigned char)_errorReplyCode;
  _dnsHeader->QDCount = 0;

  _udp.beginPacket(_udp.remoteIP(), _udp.remotePort());
  _udp.write(_buffer, sizeof(DNSHeader));
  _udp.endPacket();
}
