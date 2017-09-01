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

#define LOG_ERROR(msg) std::cout << msg << std::endl
#ifndef CHECK_AND_ASSERT_MES
#define CHECK_AND_ASSERT_MES(expr, fail_ret_val, message)   do{if(!(expr)) {LOG_ERROR(message); return fail_ret_val;};}while(0)
#endif

void callback(char* data, void* hint) {
	free(data);
}

using namespace node;
using namespace v8;
using namespace CryptoNote;
using namespace Common;

bool parse_and_validate_block_from_blob(const std::string& b_blob, Block& b)
{
	BinaryArray blob;// = fromHex(b_blob);
	bool r = fromBinaryArray(b, blob);
	CHECK_AND_ASSERT_MES(r, false, "Failed to parse Block from blob");
	return true;
}

bool block_to_blob(const Block& b, std::string &blob)
{
	return false;
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
}

void get_block_id(const Nan::FunctionCallbackInfo<v8::Value>& info) {
}

NAN_METHOD(convert_blob) {
}

void convert_blob_bb(const Nan::FunctionCallbackInfo<v8::Value>& info) {
}

void address_decode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
}


static bool fillExtra(Block& block1, const Block& block2) {
	return true;
}

static bool mergeBlocks(const Block& block1, Block& block2, const std::vector<Crypto::Hash>& branch2) {
	return true;
}

static bool construct_parent_block(const Block& b, Block& parentBlock) {
	return false;
}

NAN_METHOD(convert_blob_fa) {
}

void construct_block_blob_fa(const Nan::FunctionCallbackInfo<v8::Value>& info) {
}

void address_decode_integrated(const Nan::FunctionCallbackInfo<v8::Value>& info) {
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