﻿// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <WinSock2.h>
#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_basic_impl.h"
#include "string_tools.h"
#include "serialization/binary_utils.h"
#include "serialization/vector.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "common/base58.h"
#include "crypto/hash.h"
#include "common/int-util.h"
#include <stdio.h>
#include <limits>

namespace cryptonote {

  /************************************************************************/
  /* Cryptonote helper functions                                          */
  /************************************************************************/
  //-----------------------------------------------------------------------------------------------
	size_t get_min_block_size(uint8_t version)
	{
		if (version < 2)
			return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
		if (version < 5)
			return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
		return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
	}
	size_t get_max_block_size()
	{
		return CRYPTONOTE_MAX_BLOCK_SIZE;
	}
	//-----------------------------------------------------------------------------------------------
	size_t get_max_tx_size()
	{
		return CRYPTONOTE_MAX_TX_SIZE;
	}
  //-----------------------------------------------------------------------------------------------
#if 1
	bool get_block_reward(size_t median_size, size_t current_block_size, uint64_t already_generated_coins, uint64_t &reward, uint8_t version) {
		static_assert(DIFFICULTY_TARGET_V2 % 60 == 0 && DIFFICULTY_TARGET_V1 % 60 == 0, "difficulty targets must be a multiple of 60");
		const int target = version < 2 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
		const int target_minutes = target / 60;
		const int emission_speed_factor = EMISSION_SPEED_FACTOR_PER_MINUTE - (target_minutes - 1);

		uint64_t base_reward = (MONEY_SUPPLY - already_generated_coins) >> emission_speed_factor;
		if (base_reward < FINAL_SUBSIDY_PER_MINUTE*target_minutes)
		{
			base_reward = FINAL_SUBSIDY_PER_MINUTE*target_minutes;
		}

		uint64_t full_reward_zone = get_min_block_size(version);

		//make it soft
		if (median_size < full_reward_zone) {
			median_size = full_reward_zone;
		}

		if (current_block_size <= median_size) {
			reward = base_reward;
			return true;
		}

		if (current_block_size > 2 * median_size) {
			std::cout << "Block cumulative size is too big: " << current_block_size << ", expected less than " << 2 * median_size;
			return false;
		}
		assert(median_size < (std::numeric_limits<uint32_t>::max)());
		assert(current_block_size < (std::numeric_limits<uint32_t>::max)());

		uint64_t product_hi;
		// BUGFIX: 32-bit saturation bug (e.g. ARM7), the result was being
		// treated as 32-bit by default.
		uint64_t multiplicand = 2 * median_size - current_block_size;
		multiplicand *= current_block_size;
		uint64_t product_lo = mul128(base_reward, multiplicand, &product_hi);

		uint64_t reward_hi;
		uint64_t reward_lo;
		div128_32(product_hi, product_lo, static_cast<uint32_t>(median_size), &reward_hi, &reward_lo);
		div128_32(reward_hi, reward_lo, static_cast<uint32_t>(median_size), &reward_hi, &reward_lo);
		assert(0 == reward_hi);
		assert(reward_lo < base_reward);

		reward = reward_lo;
		return true;
	}
#else
  bool get_block_reward(size_t median_size, size_t current_block_size, uint64_t already_generated_coins, uint64_t &reward) {
    uint64_t base_reward = (MONEY_SUPPLY - already_generated_coins) >> EMISSION_SPEED_FACTOR;

    //make it soft
    if (median_size < CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE) {
      median_size = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
    }

    if (current_block_size <= median_size) {
      reward = base_reward;
      return true;
    }

    if(current_block_size > 2 * median_size) {
      LOG_PRINT_L4("Block cumulative size is too big: " << current_block_size << ", expected less than " << 2 * median_size);
      return false;
    }

    assert(median_size < std::numeric_limits<uint32_t>::max());
    assert(current_block_size < std::numeric_limits<uint32_t>::max());

    uint64_t product_hi;
    uint64_t product_lo = mul128(base_reward, current_block_size * (2 * median_size - current_block_size), &product_hi);

    uint64_t reward_hi;
    uint64_t reward_lo;
    div128_32(product_hi, product_lo, static_cast<uint32_t>(median_size), &reward_hi, &reward_lo);
    div128_32(reward_hi, reward_lo, static_cast<uint32_t>(median_size), &reward_hi, &reward_lo);
    assert(0 == reward_hi);
    assert(reward_lo < base_reward);

    reward = reward_lo;
    return true;
  }
#endif
  //------------------------------------------------------------------------------------
  uint8_t get_account_address_checksum(const public_address_outer_blob& bl)
  {
    const unsigned char* pbuf = reinterpret_cast<const unsigned char*>(&bl);
    uint8_t summ = 0;
    for(size_t i = 0; i!= sizeof(public_address_outer_blob)-1; i++)
      summ += pbuf[i];

    return summ;
  }
  std::string get_account_address_as_str(
	  network_type nettype
	  , bool subaddress
	  , account_public_address const & adr
  )
  {
	  uint64_t address_prefix = nettype == TESTNET ?
		  (subaddress ? config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX) : nettype == STAGENET ?
		  (subaddress ? config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX) :
		  (subaddress ? config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);

	  return tools::base58::encode_addr(address_prefix, t_serializable_object_to_blob(adr));
  }
  //-----------------------------------------------------------------------
  std::string get_account_address_as_str(const account_public_address& adr)
  {
    return tools::base58::encode_addr(config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX, t_serializable_object_to_blob(adr));
  }
  //-----------------------------------------------------------------------
  bool is_coinbase(const transaction& tx)
  {
    if(tx.vin.size() != 1)
      return false;

    if(tx.vin[0].type() != typeid(txin_gen))
      return false;

    return true;
  }
  //-----------------------------------------------------------------------
  bool get_account_address_from_str(
	  address_parse_info& info
	  , network_type nettype
	  , std::string const & str
  )
  {
	  uint64_t address_prefix = nettype == TESTNET ?
		  config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX : nettype == STAGENET ?
		  config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
	  uint64_t integrated_address_prefix = nettype == TESTNET ?
		  config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : nettype == STAGENET ?
		  config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
	  uint64_t subaddress_prefix = nettype == TESTNET ?
		  config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : nettype == STAGENET ?
		  config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX : config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;

	  if (2 * sizeof(public_address_outer_blob) != str.size())
	  {
		  blobdata data;
		  uint64_t prefix;
		  if (!tools::base58::decode_addr(str, prefix, data))
		  {
			  LOG_PRINT_L2("Invalid address format");
			  return false;
		  }

		  if (integrated_address_prefix == prefix)
		  {
			  info.is_subaddress = false;
			  info.has_payment_id = true;
		  }
		  else if (address_prefix == prefix)
		  {
			  info.is_subaddress = false;
			  info.has_payment_id = false;
		  }
		  else if (subaddress_prefix == prefix)
		  {
			  info.is_subaddress = true;
			  info.has_payment_id = false;
		  }
		  else {
			  LOG_PRINT_L1("Wrong address prefix: " << prefix << ", expected " << address_prefix
				  << " or " << integrated_address_prefix
				  << " or " << subaddress_prefix);
			  return false;
		  }

		  if (info.has_payment_id)
		  {
			  integrated_address iadr;
			  if (!::serialization::parse_binary(data, iadr))
			  {
				  LOG_PRINT_L1("Account public address keys can't be parsed");
				  return false;
			  }
			  info.address = iadr.adr;
			  info.payment_id = iadr.payment_id;
		  }
		  else
		  {
			  if (!::serialization::parse_binary(data, info.address))
			  {
				  LOG_PRINT_L1("Account public address keys can't be parsed");
				  return false;
			  }
		  }

		  if (!crypto::check_key(info.address.m_spend_public_key) || !crypto::check_key(info.address.m_view_public_key))
		  {
			  LOG_PRINT_L1("Failed to validate address keys");
			  return false;
		  }
	  }
	  else
	  {
		  // Old address format
		  std::string buff;
		  if (!string_tools::parse_hexstr_to_binbuff(str, buff))
			  return false;

		  if (buff.size() != sizeof(public_address_outer_blob))
		  {
			  LOG_PRINT_L1("Wrong public address size: " << buff.size() << ", expected size: " << sizeof(public_address_outer_blob));
			  return false;
		  }

		  public_address_outer_blob blob = *reinterpret_cast<const public_address_outer_blob*>(buff.data());


		  if (blob.m_ver > CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER)
		  {
			  LOG_PRINT_L1("Unknown version of public address: " << blob.m_ver << ", expected " << CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER);
			  return false;
		  }

		  if (blob.check_sum != get_account_address_checksum(blob))
		  {
			  LOG_PRINT_L1("Wrong public address checksum");
			  return false;
		  }

		  //we success
		  info.address = blob.m_address;
		  info.is_subaddress = false;
		  info.has_payment_id = false;
	  }

	  return true;
  }

  bool operator ==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
  }

  bool operator ==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
  }
}

//--------------------------------------------------------------------------------
bool parse_hash256(const std::string str_hash, crypto::hash& hash)
{
  std::string buf;
  bool res = epee::string_tools::parse_hexstr_to_binbuff(str_hash, buf);
  if (!res || buf.size() != sizeof(crypto::hash))
  {
    std::cout << "invalid hash format: <" << str_hash << '>' << std::endl;
    return false;
  }
  else
  {
    buf.copy(reinterpret_cast<char *>(&hash), sizeof(crypto::hash));
    return true;
  }
}
