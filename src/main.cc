#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <nan.h>

#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "Common/StringTools.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryInputStreamSerializer.cpp"
#include "Serialization/BinaryOutputStreamSerializer.cpp"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "CryptoTypes.h"
#include "CryptoNoteConfig.h"
#include "Common/Base58.h"

#include <misc_log_ex.h>
#include <misc_language.h>

#define LOG_ERROR(msg) std::cout << msg << std::endl
#ifndef CHECK_AND_ASSERT_MES
#define CHECK_AND_ASSERT_MES(expr, fail_ret_val, message)   do{if(!(expr)) {LOG_ERROR(message); return fail_ret_val;};}while(0)
#endif

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
	free(data);
}

using namespace node;
using namespace v8;
using namespace CryptoNote;
using namespace Common;

bool parse_and_validate_block_from_blob(const std::string& b_blob, Block& b)
{
	BinaryArray blob = fromHex(b_blob);
	bool r = fromBinaryArray(b, blob);
	CHECK_AND_ASSERT_MES(r, false, "Failed to parse Block from blob");
	return true;
}

bool block_to_blob(const Block& b, std::string &blob)
{
	BinaryArray block_blob = toBinaryArray(b);
	std::string blocktemplate_blob = toHex(block_blob);
	blob = blocktemplate_blob;
	return blocktemplate_blob.length() > 0;
}

std::string uint64be_to_blob(uint64_t num) {
	std::string res = "        ";
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

	std::string block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
	std::string output = "";

	Block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(block_template_blob, b))
		return THROW_ERROR_EXCEPTION("Failed to parse Block");
	b.nonce = nonce;
	if (!block_to_blob(b, output))
		return THROW_ERROR_EXCEPTION("Failed to convert Block to blob");

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

	std::string input = std::string(Buffer::Data(target), Buffer::Length(target));
	std::string output = "";

	Block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(input, b))
		return THROW_ERROR_EXCEPTION("Failed to parse Block");

	Crypto::Hash block_id;
	if (!get_block_hash(b, block_id))
		return THROW_ERROR_EXCEPTION("Failed to calculate hash for Block");

	char *cstr = reinterpret_cast<char*>(&block_id);
	v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

NAN_METHOD(convert_blob) {
	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	Local<Object> target = info[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	std::string input = std::string(Buffer::Data(target), Buffer::Length(target));
	BinaryArray output;

	//convert
	Block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(input, b))
		return THROW_ERROR_EXCEPTION("Failed to parse Block");

	if (!get_block_hashing_blob(b, output))
		return THROW_ERROR_EXCEPTION("Failed to create mining Block");

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

	std::string input = std::string(Buffer::Data(target), Buffer::Length(target));
	BinaryArray output;

	//convert
	Block b = AUTO_VAL_INIT(b);
	if (!parse_and_validate_block_from_blob(input, b)) {
		return THROW_ERROR_EXCEPTION("Failed to parse Block");
	}
	if (!get_block_hashing_blob(b, output))
		return THROW_ERROR_EXCEPTION("Failed to create mining Block");

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

	std::string input = std::string(Buffer::Data(target), Buffer::Length(target));

	std::string data;
	uint64_t prefix;
	if (!Tools::Base58::decode_addr(input, prefix, data))
	{
		info.GetReturnValue().Set(Nan::Undefined());
	}
	//    info.GetReturnValue().Set(Nan::Undefined());

	AccountPublicAddress adr;
	if (!fromBinaryArray(adr, asBinaryArray(data))
		|| !check_key(adr.spendPublicKey)
		|| !check_key(adr.viewPublicKey))
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


static bool fillExtra(Block& block1, const Block& block2) {
	TransactionExtraMergeMiningTag mm_tag;
    mm_tag.depth = 0;
    if (!get_aux_block_header_hash(block2, mm_tag.merkleRoot))
        return false;

    block1.baseTransaction.extra.clear();
	if (!appendMergeMiningTagToExtra(block1.baseTransaction.extra, mm_tag))
        return false;

    return true;
}

static bool mergeBlocks(const Block& block1, Block& block2, const std::vector<Crypto::Hash>& branch2) {
    block2.timestamp = block1.timestamp;
    block2.parentBlock.majorVersion = block1.majorVersion;
    block2.parentBlock.minorVersion = block1.minorVersion;
    block2.parentBlock.previousBlockHash = block1.previousBlockHash;
   // block2.parentBlock.nonce = block1.nonce;
    block2.parentBlock.baseTransaction = block1.baseTransaction;
    block2.parentBlock.transactionCount = block1.transactionHashes.size() + 1;
    block2.parentBlock.baseTransactionBranch.resize(Crypto::tree_depth(block1.transactionHashes.size() + 1));
    std::vector<Crypto::Hash> transactionHashes;

	Crypto::Hash minerTxHash;
	if (!getObjectHash(block1.baseTransaction, minerTxHash)) {
		return false;
	}
    transactionHashes.push_back(minerTxHash);
    std::copy(block1.transactionHashes.begin(), block1.transactionHashes.end(), std::back_inserter(transactionHashes));
    tree_branch(transactionHashes.data(), transactionHashes.size(), block2.parentBlock.baseTransactionBranch.data());
    block2.parentBlock.blockchainBranch = branch2;
	return true;
}

static bool construct_parent_block(const Block& b, Block& parentBlock) {
    parentBlock.majorVersion = 1;
    parentBlock.minorVersion = 0;
    parentBlock.timestamp = b.timestamp;
    parentBlock.previousBlockHash = b.previousBlockHash;
    parentBlock.nonce = b.nonce;
    parentBlock.baseTransaction.version = CURRENT_TRANSACTION_VERSION;
    parentBlock.baseTransaction.unlockTime = 0;

    return fillExtra(parentBlock, b);

}

NAN_METHOD(convert_blob_fa) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    std::string input = std::string(Buffer::Data(target), Buffer::Length(target));
	BinaryArray output;

    //convert
    Block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        return THROW_ERROR_EXCEPTION("Failed to parse Block");

     else {
        Block parentBlock;
        if (!construct_parent_block(b, parentBlock))
            return THROW_ERROR_EXCEPTION("Failed to construct parent Block");

        if (!get_block_hashing_blob(parentBlock, output))
            return THROW_ERROR_EXCEPTION("Failed to create mining Block");
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

    std::string block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    std::string output = "";

    Block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(block_template_blob, b))
        return THROW_ERROR_EXCEPTION("Failed to parse Block");

    b.nonce = nonce;
    if (b.majorVersion == BLOCK_MAJOR_VERSION_2) {
        Block parentBlock;
       // b.parentBlock.nonce = nonce;
        if (!construct_parent_block(b, parentBlock))
            return THROW_ERROR_EXCEPTION("Failed to construct parent Block");

        if (!mergeBlocks(parentBlock, b, std::vector<Crypto::Hash>()))
            return THROW_ERROR_EXCEPTION("Failed to postprocess mining Block");
    }

    if (!block_to_blob(b, output))
        return THROW_ERROR_EXCEPTION("Failed to convert Block to blob");

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

void address_decode_integrated(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	/*
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    std::string input = std::string(Buffer::Data(target), Buffer::Length(target));

    std::string data;
    uint64_t prefix;
    if (!Tools::Base58::decode_addr(input, prefix, data))
    {
        info.GetReturnValue().Set(Nan::Undefined());
    }
    //    info.GetReturnValue().Set(Nan::Undefined());

    integrated_address iadr;
    if (!::serialization::parse_binary(data, iadr) 
		|| !Crypto::check_key(iadr.adr.m_spend_public_key)
		|| !Crypto::check_key(iadr.adr.m_view_public_key))
    {
        if(data.length())
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
	*/
}

NAN_MODULE_INIT(init) {
	Nan::Set(target, Nan::New("construct_block_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(construct_block_blob)).ToLocalChecked());
	Nan::Set(target, Nan::New("get_block_id").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_block_id)).ToLocalChecked());
	Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
	Nan::Set(target, Nan::New("convert_blob_bb").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob_bb)).ToLocalChecked());
	Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
	Nan::Set(target, Nan::New("address_decode_integrated").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode_integrated)).ToLocalChecked());
}

NODE_MODULE(cryptonote, init)