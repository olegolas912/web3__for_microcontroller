//
// Created by Okada, Takahiro on 2018/02/11.
//

#include <Util.h>
#include "Arduino.h"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "TagReader/TagReader.h"

using std::string;
using std::vector;
using std::stringstream;


// returns output (header) length
uint32_t Util::RlpEncodeWholeHeader(uint8_t* header_output, uint32_t total_len) {
    if (total_len < 55) {
        header_output[0] = (uint8_t)0xc0 + (uint8_t)total_len;
        return 1;
    } else {
        uint8_t tmp_header[8];
        memset(tmp_header, 0, 8);
        uint32_t hexdigit = 1;
        uint32_t tmp = total_len;
        while ((uint32_t)(tmp / 256) > 0) {
            tmp_header[hexdigit] = (uint8_t)(tmp % 256);
            tmp = (uint32_t)(tmp / 256);
            hexdigit++;
        }
        tmp_header[hexdigit] = (uint8_t)(tmp);
        tmp_header[0] = (uint8_t)0xf7 + (uint8_t)hexdigit;

        // fix direction for header
        uint8_t header[8];
        memset(header, 0, 8);
        header[0] = tmp_header[0];
        for (int i=0; i<hexdigit; i++) {
            header[i+1] = tmp_header[hexdigit-i];
        }

        memcpy(header_output, header, (size_t)hexdigit+1);
        return hexdigit+1;
    }
}

vector<uint8_t> Util::RlpEncodeWholeHeaderWithVector(uint32_t total_len) {
    vector<uint8_t> header_output;
    if (total_len < 55) {
        header_output.push_back((uint8_t)0xc0 + (uint8_t)total_len);
    } else {
        vector<uint8_t> tmp_header;
        uint32_t hexdigit = 1;
        uint32_t tmp = total_len;
        while ((uint32_t)(tmp / 256) > 0) {
            tmp_header.push_back((uint8_t)(tmp % 256));
            tmp = (uint32_t)(tmp / 256);
            hexdigit++;
        }
        tmp_header.push_back((uint8_t)(tmp));
        tmp_header.insert(tmp_header.begin(), 0xf7 + (uint8_t)hexdigit);

        // fix direction for header
        vector<uint8_t> header;
        header.push_back(tmp_header[0]);
        for (int i=0; i<tmp_header.size()-1; i++) {
            header.push_back(tmp_header[tmp_header.size()-1-i]);
        }

        header_output.insert(header_output.end(), header.begin(), header.end());
    }
    return header_output;
}


// returns output length
uint32_t Util::RlpEncodeItem(uint8_t* output, const uint8_t* input, uint32_t input_len) {
    if (input_len==1 && input[0] == 0x00) {
        uint8_t c[1] = {0x80};
        memcpy(output, c, 1);
        return 1;
    } else if (input_len==1 && input[0] < 128) {
        memcpy(output, input, 1);
        return 1;
    } else if (input_len <= 55) {
        uint8_t _ = (uint8_t)0x80 + (uint8_t)input_len;
        uint8_t header[] = {_};
        memcpy(output, header, 1);
        memcpy(output+1, input, (size_t)input_len);
        return input_len+1;
    } else {
        uint8_t tmp_header[8];
        memset(tmp_header, 0, 8);
        uint32_t hexdigit = 1;
        uint32_t tmp = input_len;
        while ((uint32_t)(tmp / 256) > 0) {
            tmp_header[hexdigit] = (uint8_t)(tmp % 256);
            tmp = (uint32_t)(tmp / 256);
            hexdigit++;
        }
        tmp_header[hexdigit] = (uint8_t)(tmp);
        tmp_header[0] = (uint8_t)0xb7 + (uint8_t)hexdigit;

        // fix direction for header
        uint8_t header[8];
        memset(header, 0, 8);
        header[0] = tmp_header[0];
        for (int i=0; i<hexdigit; i++) {
            header[i+1] = tmp_header[hexdigit-i];
        }

        memcpy(output, header, hexdigit+1);
        memcpy(output+hexdigit+1, input, (size_t)input_len);
        return input_len+hexdigit+1;
    }
}

vector<uint8_t> Util::RlpEncodeItemWithVector(const vector<uint8_t> input) {
    vector<uint8_t> output;
    uint16_t input_len = input.size();

    if (input_len==1 && input[0] == 0x00) {
        output.push_back(0x80);
    } else if (input_len==1 && input[0] < 128) {
        output.insert(output.end(), input.begin(), input.end());
    } else if (input_len <= 55) {
        uint8_t _ = (uint8_t)0x80 + (uint8_t)input_len;
        output.push_back(_);
        output.insert(output.end(), input.begin(), input.end());
    } else {
        vector<uint8_t> tmp_header;
        uint32_t tmp = input_len;
        while ((uint32_t)(tmp / 256) > 0) {
            tmp_header.push_back((uint8_t)(tmp % 256));
            tmp = (uint32_t)(tmp / 256);
        }
        tmp_header.push_back((uint8_t)(tmp));
        uint8_t len = tmp_header.size();// + 1;
        tmp_header.insert(tmp_header.begin(), 0xb7 + len);

        // fix direction for header
        vector<uint8_t> header;
        header.push_back(tmp_header[0]);
        uint8_t hexdigit = tmp_header.size() - 1;
        for (int i=0; i<hexdigit; i++) {
            header.push_back(tmp_header[hexdigit-i]);
        }

        output.insert(output.end(), header.begin(), header.end());
        output.insert(output.end(), input.begin(), input.end());
    }
    return output;
}

vector<uint8_t> Util::ConvertNumberToVector(unsigned long long val) 
{
	vector<uint8_t> tmp;
	vector<uint8_t> ret;
	if ((unsigned long long)(val / 256) >= 0) {
		while ((unsigned long long)(val / 256) > 0) {
			tmp.push_back((uint8_t)(val % 256));
			val = (unsigned long long)(val / 256);
		}
		tmp.push_back((uint8_t)(val % 256));
		uint8_t len = tmp.size();
		for (int i = 0; i<len; i++) {
			ret.push_back(tmp[len - i - 1]);
		}
	}
	else {
		ret.push_back((uint8_t)val);
	}
	return ret;
}

vector<uint8_t> Util::ConvertNumberToVector(uint32_t val) {
    return ConvertNumberToVector((unsigned long long) val);
}

uint32_t Util::ConvertNumberToUintArray(uint8_t *str, uint32_t val) {
    uint32_t ret = 0;
    uint8_t tmp[8];
    memset(tmp,0,8);
    if ((uint32_t)(val / 256) >= 0) {
        while ((uint32_t)(val / 256) > 0) {
            tmp[ret] = (uint8_t)(val % 256);
            val = (uint32_t)(val / 256);
            ret++;
        }
        tmp[ret] = (uint8_t)(val % 256);
        for (int i=0; i<ret+1; i++) {
            str[i] = tmp[ret-i];
        }
    } else {
        str[0] = (uint8_t)val;
    }

    return ret+1;
}

uint8_t Util::ConvertCharToByte(const uint8_t* ptr)
{
	char c[3];
	c[0] = *(ptr);
	c[1] = *(ptr + 1);
	c[2] = 0x00;
	return strtol(c, nullptr, 16);
}

vector<uint8_t> Util::ConvertHexToVector(const uint8_t *in) 
{
    const uint8_t *ptr = in;
    vector<uint8_t> out;
    if (ptr[0] == '0' && ptr[1] == 'x') ptr += 2;

	size_t lenstr = strlen((const char*)ptr);
	int i = 0;
	if ((lenstr % 2) == 1) //deal with odd sized hex strings
	{
		char c[2];
		c[0] = *ptr;
		c[1] = 0;
		out.push_back(ConvertCharToByte((const uint8_t*)c));
		i = 1;
	}
	for (; i<lenstr; i += 2)
	{
		out.push_back(ConvertCharToByte(ptr + i));
	}
	return out;
}

vector<uint8_t> Util::ConvertHexToVector(const string* str) {
    return ConvertHexToVector((uint8_t*)(str->c_str()));
}

uint32_t Util::ConvertCharStrToUintArray(uint8_t *out, const uint8_t *in) {
    uint32_t ret = 0;
    const uint8_t *ptr = in;
    // remove "0x"
    if (in[0] == '0' && in[1] == 'x') ptr += 2;

    size_t lenstr = strlen((const char*)ptr);
    for (int i=0; i<lenstr; i+=2) {
        char c[3];
        c[0] = *(ptr+i);
        c[1] = *(ptr+i+1);
        c[2] = 0x00;
        uint8_t val = strtol(c, nullptr, 16);
        out[ret] = val;
        ret++;
    }
    return ret;
};

uint8_t Util::HexToInt(uint8_t s) {
    uint8_t ret = 0;
    if(s >= '0' && s <= '9'){
        ret = uint8_t(s - '0');
    } else if(s >= 'a' && s <= 'f'){
        ret = uint8_t(s - 'a' + 10);
    } else if(s >= 'A' && s <= 'F'){
        ret = uint8_t(s - 'A' + 10);
    }
    return ret;
}

void Util::VectorToCharStr(char* str, const vector<uint8_t> buf) {
    sprintf(str, "0x");
    for (int i = 0; i < buf.size(); i++) {
        sprintf(str, "%s%02x", str, buf[i]);
    }
}

string Util::VectorToString(const vector<uint8_t> buf) 
{
    return ConvertBytesToHex((const uint8_t*)buf.data(), buf.size());
}

string Util::ConvertBytesToHex(const uint8_t *bytes, int length)
{
    size_t chSz = length*2 + 3;
    char hexString[chSz];
    char *hexPtr = hexString;
    *hexPtr++= '0';
    *hexPtr++= 'x';
    for (int i = 0; i < length; i++)
    {
        sprintf(hexPtr, "%02x", bytes[i]);
        hexPtr += 2;
    }
    *hexPtr = 0;

    return string(hexString);
}

void Util::ConvertHexToBytes(uint8_t *_dst, const char *_src, int length)
{
    if (_src[0] == '0' && _src[1] == 'x') _src += 2; //chop off 0x

    for (int i = 0; i < length; i++)
    {
        byte extract;
        char a = _src[2 * i];
        char b = _src[2 * i + 1];
        extract = HexToInt(a) << 4 | HexToInt(b);
        _dst[i] = extract;
    }
}

string  Util::ConvertBase(int from, int to, const char *s)
{
    if ( s == NULL )
    return NULL;

    if (from < 2 || from > 36 || to < 2 || to > 36) { return NULL; }

    if (s[0] == '0' && s[1] == 'x') s += 2;

    int il = strlen(s);

    int *fs = new int[il];
    int k = 0;
    int i,j;

    for (i = il - 1; i >=0; i-- )
    {
        if (s[i] >= '0' && s[i] <= '9') 
        {
            fs[k] = (int)(s[i] - '0'); 
        }
        else
        {
            if (s[i] >= 'A' && s[i] <= 'Z') 
            {
                fs[k] = 10 + (int)(s[i] - 'A'); 
            }
            else if (s[i] >= 'a' && s[i] <= 'z') 
            {
                fs[k] = 10 + (int)(s[i] - 'a'); 
            }
            else
            {
                delete[]fs;
                return NULL; 
            } //only allow 0-9 A-Z characters
        }
        k++;
    }

    for (i=0;i<il;i++)
    {
        if ( fs[i] >= from ) 
            return NULL;
    }

    double x = ceil(log( from )  / log (to));
    int ol = 1+( il * x );

    int * ts = new int[ol];
    int * cums = new int [ol];

    for (i=0;i<ol;i++)
    {
        ts[i]=0;
        cums[i]=0;
    }
    ts[0]=1;

    //evaluate the output
    for (i = 0; i < il; i++) //for each input digit
    {
        for (j = 0; j < ol; j++) //add the input digit times (base:to from^i) to the output cumulator
        {
            cums[j] += ts[j] * fs[i];
            int temp = cums[j];
            int rem = 0;
            int ip = j;
            do // fix up any remainders in base:to
            {
                rem = temp / to;
                cums[ip] = temp - rem * to; 
                ip++;
                if (ip >= ol)
                {
                    if ( rem > 0 )
                    {
                        delete[]ts;
                        delete[]cums;
                        delete[]fs;
                        return NULL;
                    }
                    break;
                }
                cums[ip] += rem;
                temp = cums[ip];
            }
            while (temp >= to);
        }

        for (j = 0; j < ol; j++)
        {
            ts[j] = ts[j] * from;
        }

        for (j = 0; j < ol; j++) //check for any remainders
        {
            int temp = ts[j];
            int rem = 0;
            int ip = j;
            do  //fix up any remainders
            {
                rem = temp / to;
                ts[ip] = temp - rem * to; 
                ip++;
                if (ip >= ol)
                {          
                    if ( rem > 0 )
                    {
                        delete[]ts;
                        delete[]cums;
                        delete[]fs;
                        return NULL;
                    }
                    break;
                }
                ts[ip] += rem;
                temp = ts[ip];
            }
            while (temp >= to);
        }
    }

    char out[sizeof(char) * (ol + 1)];

    int spos = 0;
    bool first = false; //leading zero flag
    for (i = ol-1; i >= 0; i--)
    {
        if (cums[i] != 0) 
        { 
            first = true; 
        }
        if (!first) 
        { 
            continue; 
        }

        if (cums[i] < 10) 
        { 			
            out[spos] = (char)(cums[i] + '0'); 
        }
        else 
        { 			
            out[spos] = (char)(cums[i] + 'A' - 10); 
        }
        spos ++;
    }
    out[spos]=0;

    delete[]ts;
    delete[]cums;
    delete[]fs;

    return string(out);
}

string Util::ConvertDecimal(int decimals, string *result)
{
    int decimalLocation = result->length() - decimals;
	string newValue = "";
	if (decimalLocation <= 0)
	{
		newValue += "0.";
		for (; decimalLocation < 0; decimalLocation++)
		{
			newValue += "0";
		}
		newValue += *result;
	}
	else
	{
		//need to insert the point within the string
		newValue = result->substr(0, decimalLocation);
		newValue += ".";
		newValue += result->substr(decimalLocation);
	}

    return newValue;
}

string Util::ConvertHexToASCII(const char *result, size_t length)
{
	//convert hex to string.
	//first trim all the zeros
	int index = 0;
	string converted = "";
	char reader;
	int state = 0;
	bool endOfString = false;

	//No ASCII is less than 16 so this is safe
	while (index < length && (result[index] == '0' || result[index] == 'x')) index++;

	while (index < length && endOfString == false)
	{
		// convert from hex to ascii
		char c = result[index];
		switch (state)
		{
		case 0:
			reader = (char)(Util::HexToInt(c) * 16);
			state = 1;
			break;
		case 1:
			reader += (char)Util::HexToInt(c);
			if (reader == 0)
			{
				endOfString = true;
			}
			else
			{
				converted += reader;
				state = 0;
			}
			break;
		}
		index++;
	}

	return converted;  
}

/**
 * Build a std::vector of bytes32 as hex strings
 **/
vector<string>* Util::ConvertCharStrToVector32(const char *resultPtr, size_t resultSize, vector<string> *result) 
{
	if (resultSize < 64) return result;
    if (resultPtr[0] == '0' && resultPtr[1] == 'x') resultPtr += 2;
	//estimate size of return
	int returnSize = resultSize / 64;
	result->reserve(returnSize);
    int index = 0;
    char element[65];
    element[64] = 0;

    while (index <= (resultSize - 64))
    {
        memcpy(element, resultPtr, 64);
        result->push_back(string(element));
        resultPtr += 64;
        index += 64;
    }

	return result;
}

string Util::InterpretStringResult(const char *result)
{
    //convert to vector bytes32
    string retVal = "";

    if (result != NULL && strlen(result) > 0) 
    {
        vector<string> breakDown;
        Util::ConvertCharStrToVector32(result, strlen(result), &breakDown);

        if (breakDown.size() > 2)
        {
            //check first value
            auto itr = breakDown.begin();
            long dyn = strtol(itr++->c_str(), NULL, 16);
            if (dyn == 32) //array marker
            {
                long length = strtol(itr++->c_str(), NULL, 16);
                //now get a pointer to string immediately after the length marker
                const char *strPtr = result + 2 + (2*64);
                retVal = ConvertHexToASCII(strPtr, length*2);
            }
        }
    }

    return retVal;
}

vector<string> *Util::InterpretVectorResult(string *result)
{
    vector<string> *retVal = new vector<string>();
    TagReader reader;
    const char *value = reader.getTag(result, "result");

    if (value != NULL && strlen(value) > 0) 
    {
        vector<string> breakDown;
        Util::ConvertCharStrToVector32(value, reader.length(), &breakDown);

        if (breakDown.size() > 2)
        {
            //check first value
            auto itr = breakDown.begin();
            long dyn = strtol(itr++->c_str(), NULL, 16);
            if (dyn == 32) //array marker
            {
                long length = strtol(itr++->c_str(), NULL, 16);
                
                //checksum
                if (breakDown.size() != (length + 2))
                {
                    Serial.println("Bad array result data.");
                    for (itr = breakDown.begin(); itr != breakDown.end(); itr++) Serial.println(*itr->c_str());
                }
                for (;itr != breakDown.end(); itr++)
                {
                    retVal->push_back(*itr);
                }   
            }
        }
    }

    return retVal;
}

void Util::PadForward(string *target, int targetSize)
{
    int remain = (targetSize*2) - (target->length() % targetSize);
    char buffer[remain+1];
    memset(buffer, '0', remain);
    buffer[remain] = 0;
    *target = buffer + *target;
}

string Util::ConvertEthToWei(double eth)
{
	//wei is eth x 10^18.
	double weiValue = eth * pow(10.0, 18.0);
	char buffer[32];
	snprintf(buffer, sizeof(buffer), "%0.1f", weiValue);
	string weiStr = buffer;
	//prune decimal
	int index = weiStr.find_last_of('.');
	if (index > 0) weiStr = weiStr.substr(0, index);

	//now convert this to base 16
	return ConvertBase(10, 16, weiStr.c_str());
}

size_t Util::GetNumberSize(unsigned long long number) {
    size_t size = 0;
    if (number == 0) return 1;
    while (number) {
        number /= 256;
        size++;
    }
    return size;
}

size_t Util::RlpEncodeItemSize(size_t itemSize) {
    if (itemSize <= 55) {
        return 1;
    } else {
        size_t lenSize = 0;
        size_t tmp = itemSize;
        while (tmp) {
            tmp /= 256;
            lenSize++;
        }
        return 1 + lenSize;
    }
}

size_t Util::RlpEncodeListHeader(size_t totalSize, uint8_t *buffer, size_t bufferSize) {
    if (totalSize <= 55) {
        if (bufferSize < 1) return 0;
        buffer[0] = 0xC0 + totalSize;
        return 1;
    } else {
        size_t lenSize = 0;
        size_t tmp = totalSize;
        while (tmp) {
            tmp /= 256;
            lenSize++;
        }
        if (bufferSize < 1 + lenSize) return 0;
        buffer[0] = 0xF7 + lenSize;
        for (size_t i = 0; i < lenSize; ++i) {
            buffer[1 + lenSize - 1 - i] = (totalSize >> (8 * i)) & 0xFF;
        }
        return 1 + lenSize;
    }
}