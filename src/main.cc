#ifdef _MSC_VER
#include <WinSock2.h>
#endif

#include "cryptonote_core/cryptonote_basic.h"
 #include "cryptonote_core/cryptonote_format_utils.h"
 #include "cryptonote_protocol/blobdatatype.h"
 #include "crypto/crypto.h"
 #include "crypto/hash.h"
 #include "common/base58.h"
 #include "serialization/binary_utils.h"
#include "cryptonote_core/blobdatatype.h"
#include <node.h>
#include <v8.h>
#include <nan.h>
#include <algorithm>
#include <cmath>
#include <node_buffer.h>
#include <stdint.h>
#include <string>

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
  free(data);
}

using namespace node;
using namespace v8;
using namespace cryptonote;

#if 1

NAN_METHOD(convert_blob) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");

	output = get_block_hashing_blob(b);
    if (output.size() <= 0)
        return THROW_ERROR_EXCEPTION("Failed to create mining block");
    
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

#if 0
blobdata uint64be_to_blob(uint64_t num) {
	blobdata res = "        ";
	res[0] = num >> 56 & 0xff;
	res[1] = num >> 48 & 0xff;
	res[2] = num >> 40 & 0xff;
	res[3] = num >> 32 & 0xff;
	res[4] = num >> 24 & 0xff;
	res[5] = num >> 16 & 0xff;
	res[6] = num >> 8 & 0xff;
	res[7] = num & 0xff;
	return res;
}

static bool fillExtra(cryptonote::block& block1, const cryptonote::block& block2) {
	cryptonote::tx_extra_merge_mining_tag mm_tag;
	mm_tag.depth = 0;
	if (!cryptonote::get_block_header_hash(block2, mm_tag.merkle_root))
		return false;

	block1.miner_tx.extra.clear();
	if (!cryptonote::append_mm_tag_to_extra(block1.miner_tx.extra, mm_tag))
		return false;

	return true;
}

static bool mergeBlocks(const cryptonote::block& block1, cryptonote::block& block2, const std::vector<crypto::hash>& branch2) {
	block2.timestamp = block1.timestamp;
	block2.parent_block.major_version = block1.major_version;
	block2.parent_block.minor_version = block1.minor_version;
	block2.parent_block.prev_id = block1.prev_id;
	block2.parent_block.nonce = block1.nonce;
	block2.parent_block.miner_tx = block1.miner_tx;
	block2.parent_block.number_of_transactions = block1.tx_hashes.size() + 1;
	block2.parent_block.miner_tx_branch.resize(crypto::tree_depth(block1.tx_hashes.size() + 1));
	std::vector<crypto::hash> transactionHashes;
	transactionHashes.push_back(cryptonote::get_transaction_hash(block1.miner_tx));
	std::copy(block1.tx_hashes.begin(), block1.tx_hashes.end(), std::back_inserter(transactionHashes));
	tree_branch(transactionHashes.data(), transactionHashes.size(), block2.parent_block.miner_tx_branch.data());
	block2.parent_block.blockchain_branch = branch2;
	return true;
}

static bool construct_parent_block(const cryptonote::block& b, cryptonote::block& parent_block) {
	parent_block.major_version = 1;
	parent_block.minor_version = 0;
	parent_block.timestamp = b.timestamp;
	parent_block.prev_id = b.prev_id;
	parent_block.nonce = b.parent_block.nonce;
	parent_block.miner_tx.version = CURRENT_TRANSACTION_VERSION;
	parent_block.miner_tx.unlock_time = 0;

	return fillExtra(parent_block, b);
}

NAN_METHOD(convert_blob_fa) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");

     else {
        block parent_block;
        if (!construct_parent_block(b, parent_block))
            return THROW_ERROR_EXCEPTION("Failed to construct parent block");

        if (!get_block_hashing_blob(parent_block, output))
            return THROW_ERROR_EXCEPTION("Failed to create mining block");
    }
//    Local<Object> v8::Local<v8::Value> returnValue =  Nan::NewBuffer(output.length()).ToLocalChecked();
//    memcpy(Buffer::Data(returnValue), output.c_str(), output.length());
//    info.GetReturnValue().Set(
//        returnValue
//    );
    
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

void get_block_id(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");

    crypto::hash block_id;
    if (!get_block_hash(b, block_id))
        return THROW_ERROR_EXCEPTION("Failed to calculate hash for block");
    
    char *cstr = reinterpret_cast<char*>(&block_id);
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

void construct_block_blob_fa(const Nan::FunctionCallbackInfo<v8::Value>& info) {

	if (info.Length() < 2)
		return THROW_ERROR_EXCEPTION("You must provide two arguments.");

	Local<Object> block_template_buf = info[0]->ToObject();
	Local<Object> nonce_buf = info[1]->ToObject();

	if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf))
		return THROW_ERROR_EXCEPTION("Both arguments should be buffer objects.");

	if (Buffer::Length(nonce_buf) != 4)
		return THROW_ERROR_EXCEPTION("Nonce buffer has invalid size.");

	uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));

	blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
	blobdata output = "";

	block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(block_template_blob, b))
		return THROW_ERROR_EXCEPTION("Failed to parse block");

	b.nonce = nonce;
	if (b.major_version == BLOCK_MAJOR_VERSION_2) {
		block parent_block;
		b.parent_block.nonce = nonce;
		if (!construct_parent_block(b, parent_block))
			return THROW_ERROR_EXCEPTION("Failed to construct parent block");

		if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>()))
			return THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
	}

	if (!block_to_blob(b, output))
		return THROW_ERROR_EXCEPTION("Failed to convert block to blob");

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void convert_blob_bb(const Nan::FunctionCallbackInfo<v8::Value>& info) {

	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	Local<Object> target = info[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
	blobdata output = "";

	//convert
	bb_block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(input, b)) {
		return THROW_ERROR_EXCEPTION("Failed to parse block");
	}
	output = get_block_hashing_blob(b);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void address_decode(const Nan::FunctionCallbackInfo<v8::Value>& info) {

	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	Local<Object> target = info[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

	blobdata data;
	uint64_t prefix;
	if (!tools::base58::decode_addr(input, prefix, data))
	{
		info.GetReturnValue().Set(Nan::Undefined());
	}
	//    info.GetReturnValue().Set(Nan::Undefined());


	account_public_address adr;
	if (!::serialization::parse_binary(data, adr) || !crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key))
	{
		if (data.length())
		{
			data = uint64be_to_blob(prefix) + data;
		}
		else
		{
			info.GetReturnValue().Set(Nan::Undefined());
		}
		v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)data.data(), data.size()).ToLocalChecked();
		info.GetReturnValue().Set(
			returnValue
		);

	}
	else
	{
		info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
	}
}

void address_decode_integrated(const Nan::FunctionCallbackInfo<v8::Value>& info) {

	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	Local<Object> target = info[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

	blobdata data;
	uint64_t prefix;
	if (!tools::base58::decode_addr(input, prefix, data))
	{
		info.GetReturnValue().Set(Nan::Undefined());
	}
	//    info.GetReturnValue().Set(Nan::Undefined());


	integrated_address iadr;
	if (!::serialization::parse_binary(data, iadr) || !crypto::check_key(iadr.adr.m_spend_public_key) || !crypto::check_key(iadr.adr.m_view_public_key))
	{
		if (data.length())
		{
			data = uint64be_to_blob(prefix) + data;
		}
		else
		{
			info.GetReturnValue().Set(Nan::Undefined());
		}
		v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)data.data(), data.size()).ToLocalChecked();
		info.GetReturnValue().Set(
			returnValue
		);

	}
	else
	{
		info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
	}
}

#endif

void construct_block_blob(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> block_template_buf = info[0]->ToObject();
    Local<Object> nonce_buf = info[1]->ToObject();

    if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf))
        return THROW_ERROR_EXCEPTION("Both arguments should be buffer objects.");

    if (Buffer::Length(nonce_buf) != 4)
        return THROW_ERROR_EXCEPTION("Nonce buffer has invalid size.");

    uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));

    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(block_template_blob, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");
    b.nonce = nonce;
    if (!block_to_blob(b, output))
        return THROW_ERROR_EXCEPTION("Failed to convert block to blob");

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("construct_block_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(construct_block_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
}

#if 0
Nan::Set(target, Nan::New("get_block_id").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_block_id)).ToLocalChecked());
Nan::Set(target, Nan::New("convert_blob_bb").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob_bb)).ToLocalChecked());
Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
Nan::Set(target, Nan::New("address_decode_integrated").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode_integrated)).ToLocalChecked());
#endif

NODE_MODULE(cryptonote, init)

#else

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static int x2d(char x)
{
	int d = 0;

	if (isdigit(x))
	{
		d = x - '0';
	}
	else if (isxdigit(x))
	{
		d = toupper(x) - 'A' + 0xA;
	}

	return d;
}
static void StringToByteArray(
	const char* string_in,
	char* byte_array_out,
	int   byte_array_length_in,
	int * byte_array_length_out
)
{
	int byte_array_idx = 0;
	if (string_in == NULL ||
		byte_array_length_in == 0 ||
		byte_array_out == NULL ||
		byte_array_length_out == NULL)
	{
		return;
	}
	for (byte_array_idx = 0; byte_array_idx < byte_array_length_in; ++byte_array_idx)
	{
		if (*(string_in) == '\0' ||
			*(string_in + 1) == '\0')
		{
			break;
		}
		if (!isxdigit(*(string_in)) ||
			!isxdigit(*(string_in + 1)))
		{
			break;
		}

		byte_array_out[byte_array_idx] = x2d(*(string_in)) << 4 | x2d(*(string_in + 1));
		string_in += 2;
	}
	*byte_array_length_out = byte_array_idx;
}

bool TestConvert_blob(void)
{
	const char inputStr[] = "06069da8c8d50526a1a4cba7ff9f24e61728bd94b07009c9497b19674fc1ad0b837a6c6f6fb4c30000000002f6d35d01ffbad35d01bd8fcab0f0900102dfce431f23e19e57341926bcd42553f97256b5640e41c56b4c48808258228b0e340102098e4fbbb3e461e793565aeb9d766731d369fcc44b23e74f23a6382db86310021100000003e93812ba9c000000010000000100019a60d569218a0383eb8cd3857f5e0133c66fea1a49efff06a03f564f389a1cd9";
	char result[] = "06069da8c8d50526a1a4cba7ff9f24e61728bd94b07009c9497b19674fc1ad0b837a6c6f6fb4c3000000006810705fb6226670e36888931573ae958c3c6848c2be8a299214da048201d0cf02";

	char byte_array[1600] = { 0 };
	int length = 0;
	StringToByteArray(inputStr, byte_array, sizeof(byte_array), &length);

	char byte_array_output[1600] = { 0 };
	int length_output = 0;
	StringToByteArray(result, byte_array_output, sizeof(byte_array_output), &length_output);

	blobdata input = std::string(byte_array, length);
	blobdata output = "";

	//convert
	block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(input, b))
	{
		return false;//THROW_ERROR_EXCEPTION("Failed to parse block");
	}
	output = get_block_hashing_blob(b);
	if (output.size() <= 0)
	{
		return false; // THROW_ERROR_EXCEPTION("Failed to create mining block");
	}
	if (length_output > 0
		&& length_output == output.length())
	{
		const char *ptr = output.c_str();

^		if (memcmp(byte_array_output, output.c_str(), output.length()) == 0)
		{
			return true;
		}
	}
	return false;
}

int main(int argc, char *argv[])
{
#if 1
	if (TestConvert_blob())
	{
		printf("TestConvert_blob Pass\n");
	}
	else
	{
		printf("TestConvert_blob Faild\n");
	}
	getchar();
#endif
}

#endif