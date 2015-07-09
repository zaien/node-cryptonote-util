// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/variant.hpp>
#include <boost/functional/hash/hash.hpp>
#include <iostream>
#include <vector>
#include <cstring>  // memcmp
#include <sstream>
#include "serialization/serialization.h"
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/debug_archive.h"
#include "serialization/crypto.h"
#include "serialization/keyvalue_serialization.h" // eepe named serialization
#include "string_tools.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "misc_language.h"
#include "tx_extra.h"
#include "block_flags.h"

namespace cryptonote
{
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()
  };
  struct block;
  class transaction;
  struct tx_extra_merge_mining_tag;

  // Implemented in cryptonote_format_utils.cpp
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  bool get_mm_tag_from_extra(const std::vector<uint8_t>& tx, tx_extra_merge_mining_tag& mm_tag);

  const static crypto::hash null_hash = AUTO_VAL_INIT(null_hash);
  const static crypto::public_key null_pkey = AUTO_VAL_INIT(null_pkey);

  typedef std::vector<crypto::signature> ring_signature;


  /* outputs */

  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  #pragma pack(push, 1)
  struct bb_txout_to_key
  {
    bb_txout_to_key() { }
    bb_txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
    uint8_t mix_attr;
  };
  struct lui_txout_to_key
  {
    lui_txout_to_key() { }
    lui_txout_to_key(const crypto::public_key &_key) : key(_key) { }

    crypto::public_key key;
    uint8_t mix_attr;
  };
  #pragma pack(pop)


  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };


  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key> txin_v;

  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key> txout_target_v;
  typedef boost::variant<txout_to_script, txout_to_scripthash, bb_txout_to_key> bb_txout_target_v;
  typedef boost::variant<txout_to_script, txout_to_scripthash, lui_txout_to_key> lui_txout_target_v;

  //typedef std::pair<uint64_t, txout> out_t;
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };
  struct bb_tx_out
  {
    uint64_t amount;
    bb_txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };
  struct lui_tx_out
  {
    uint64_t amount;
    lui_txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  class transaction_prefix
  {

  public:
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    //extra
    std::vector<uint8_t> extra;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      if(CURRENT_TRANSACTION_VERSION < version) return false;
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
    END_SERIALIZE()


  protected:
    transaction_prefix(){}
  };

  class transaction: public transaction_prefix
  {
  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count

    transaction();
    virtual ~transaction();
    void set_null();

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<transaction_prefix *>(this))

      ar.tag("signatures");
      ar.begin_array();
      PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
      bool signatures_not_expected = signatures.empty();
      if (!signatures_not_expected && vin.size() != signatures.size())
        return false;

      for (size_t i = 0; i < vin.size(); ++i)
      {
        size_t signature_size = get_signature_size(vin[i]);
        if (signatures_not_expected)
        {
          if (0 == signature_size)
            continue;
          else
            return false;
        }

        PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
        if (signature_size != signatures[i].size())
          return false;

        FIELDS(signatures[i]);

        if (vin.size() - i > 1)
          ar.delimit_array();
      }
      ar.end_array();
    END_SERIALIZE()

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };

  class bb_transaction_prefix
  {

  public:
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<bb_tx_out> vout;
    //extra
    std::vector<uint8_t> extra;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
    END_SERIALIZE()


  protected:
    bb_transaction_prefix(){}
  };

  class bb_transaction: public bb_transaction_prefix
  {
  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count

    bb_transaction();
    virtual ~bb_transaction();
    void set_null();

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<bb_transaction_prefix *>(this))
      FIELD(signatures)
    END_SERIALIZE()

    static size_t get_signature_size(const txin_v& tx_in);
  };

#define OFFER_TYPE_LUI_TO_ETC   0
#define OFFER_TYPE_ETC_TO_LUI   1

  /************************************************************************/
  /* attachment structures                                                */
  /************************************************************************/
  struct offer_details
  {
    uint8_t offer_type;
    uint64_t amount_lui;       //amount of lui
    uint64_t amount_etc;       //amount of other currency or goods
    std::string bonus;            //
    std::string target;        //[max 30 characters] currency / goods
    std::string location_country;   //US
    std::string location_city;      //ChIJD7fiBh9u5kcRYJSMaMOCCwQ (google geo-autocomplete id)
    std::string contacts;      //[max 140 characters] (Skype, mail, ICQ, etc., website)
    std::string comment;       //[max 160 characters]
    std::string payment_types; //[max 20 characters ]money accept type(bank transaction, internet money, cash, etc)
    uint8_t expiration_time;   //n-days

    BEGIN_SERIALIZE_OBJECT()
      VALUE(offer_type)
      VARINT_FIELD(amount_lui)
      VARINT_FIELD(amount_etc)
      VALUE(bonus)
      VALUE(target)
      VALUE(location_country)
      VALUE(location_city)
      VALUE(contacts)
      VALUE(comment)
      VALUE(payment_types)
      VALUE(expiration_time)
    END_SERIALIZE()

  };

  /************************************************************************/
  /* attachment structures                                                */
  /************************************************************************/
  struct cancel_offer
  {
    crypto::hash tx_id;
    uint64_t offer_index;
    crypto::signature sig; //tx_id signed by transaction secrete key

    BEGIN_SERIALIZE_OBJECT()
      VALUE(tx_id)
      VALUE(offer_index)
      VALUE(sig)
    END_SERIALIZE()
  };

  struct tx_comment
  {
    std::string comment;

    BEGIN_SERIALIZE()
      FIELD(comment)
    END_SERIALIZE()
  };

  struct tx_payer
  {
    account_public_address acc_addr;

    BEGIN_SERIALIZE()
      FIELD(acc_addr)
    END_SERIALIZE()
  };

  struct tx_crypto_checksum
  {
    uint32_t summ;

    BEGIN_SERIALIZE()
      FIELD(summ)
    END_SERIALIZE()
  };

  struct tx_message
  {
    std::string msg;

    BEGIN_SERIALIZE()
      FIELD(msg)
      END_SERIALIZE()
  };

  typedef boost::variant<offer_details, tx_comment, tx_payer, tx_crypto_checksum, tx_message, std::string, cancel_offer> attachment_v;

  /************************************************************************/
  /* extra structures                                                     */
  /************************************************************************/
  struct extra_attachment_info
  {
    uint64_t sz;
    crypto::hash hsh;

    BEGIN_SERIALIZE()
      VARINT_FIELD(sz)
      FIELD(hsh)
    END_SERIALIZE()
  };

  struct extra_user_data
  {
    std::string buff;
    
    BEGIN_SERIALIZE()
      FIELD(buff)
    END_SERIALIZE()
  };

  struct extra_alias_entry
  {
    std::vector<uint8_t> buff; //manual parse
    BEGIN_SERIALIZE()
      FIELD(buff)
    END_SERIALIZE()
  };

  struct extra_padding
  {
    std::vector<uint8_t> buff; //stub
    
    BEGIN_SERIALIZE()
      FIELD(buff)
    END_SERIALIZE()
  };

  typedef boost::variant<crypto::public_key, extra_attachment_info, extra_alias_entry, extra_user_data, extra_padding> extra_v;
  
  
  
  
  
  
  class lui_transaction_prefix
  {

  public:
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<lui_tx_out> vout;
    //extra
    std::vector<extra_v> extra;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
    END_SERIALIZE()

  protected:
    lui_transaction_prefix(){}
  };


  class lui_transaction: public lui_transaction_prefix
  {
  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    std::vector<attachment_v> attachment;

    lui_transaction();
    //virtual ~transaction();
    //void set_null();

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<lui_transaction_prefix *>(this))
      FIELD(signatures)
      FIELD(attachment)
    END_SERIALIZE()


    static size_t get_signature_size(const txin_v& tx_in);
  };
  

  inline
  transaction::transaction()
  {
    set_null();
  }

  inline
  transaction::~transaction()
  {
    //set_null();
  }

  inline
  void transaction::set_null()
  {
    version = 0;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
    signatures.clear();
  }

  inline
  size_t transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_script& txin) const{return 0;}
      size_t operator()(const txin_to_scripthash& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }

  inline
  bb_transaction::bb_transaction()
  {
    set_null();
  }

  inline
  bb_transaction::~bb_transaction()
  {
    //set_null();
  }

  inline
  void bb_transaction::set_null()
  {
    version = 0;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
    signatures.clear();
  }

  inline
  size_t bb_transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_script& txin) const{return 0;}
      size_t operator()(const txin_to_scripthash& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }

  inline
  lui_transaction::lui_transaction()
  {
    version = 0;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
    signatures.clear();
    attachment.clear();
    
  }
  /*
  inline
  transaction::~transaction()
  {
    //set_null();
  }

  inline
  void transaction::set_null()
  {
    version = 0;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
    signatures.clear();
  }
  */
  inline
  size_t lui_transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& /*txin*/) const{return 0;}
      size_t operator()(const txin_to_script& /*txin*/) const{return 0;}
      size_t operator()(const txin_to_scripthash& /*txin*/) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  const uint8_t CURRENT_BYTECOIN_BLOCK_MAJOR_VERSION = 1;

  struct bytecoin_block
  {
    uint8_t major_version;
    uint8_t minor_version;
    crypto::hash prev_id;
    uint32_t nonce;
    size_t number_of_transactions;
    std::vector<crypto::hash> miner_tx_branch;
    transaction miner_tx;
    std::vector<crypto::hash> blockchain_branch;
  };

  struct serializable_bytecoin_block
  {
    bytecoin_block& b;
    uint64_t& timestamp;
    bool hashing_serialization;
    bool header_only;

    serializable_bytecoin_block(bytecoin_block& b_, uint64_t& timestamp_, bool hashing_serialization_, bool header_only_) :
      b(b_), timestamp(timestamp_), hashing_serialization(hashing_serialization_), header_only(header_only_)
    {
    }

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD_N("major_version", b.major_version);
      if(b.major_version > CURRENT_BYTECOIN_BLOCK_MAJOR_VERSION) return false;
      VARINT_FIELD_N("minor_version", b.minor_version);
      VARINT_FIELD(timestamp);
      FIELD_N("prev_id", b.prev_id);
      FIELD_N("nonce", b.nonce);

      if (hashing_serialization)
      {
        crypto::hash miner_tx_hash;
        if (!get_transaction_hash(b.miner_tx, miner_tx_hash))
          return false;

        crypto::hash merkle_root;
        crypto::tree_hash_from_branch(b.miner_tx_branch.data(), b.miner_tx_branch.size(), miner_tx_hash, 0, merkle_root);

        FIELD(merkle_root);
      }

      VARINT_FIELD_N("number_of_transactions", b.number_of_transactions);
      if (b.number_of_transactions < 1)
        return false;

      if (!header_only)
      {
        ar.tag("miner_tx_branch");
        ar.begin_array();
        size_t branch_size = crypto::tree_depth(b.number_of_transactions);
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(branch_size, const_cast<bytecoin_block&>(b).miner_tx_branch);
        if (b.miner_tx_branch.size() != branch_size)
          return false;
        for (size_t i = 0; i < branch_size; ++i)
        {
          FIELDS(b.miner_tx_branch[i]);
          if (i + 1 < branch_size)
            ar.delimit_array();
        }
        ar.end_array();

        FIELD(b.miner_tx);

        tx_extra_merge_mining_tag mm_tag;
        if (!get_mm_tag_from_extra(b.miner_tx.extra, mm_tag))
          return false;

        ar.tag("blockchain_branch");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(mm_tag.depth, const_cast<bytecoin_block&>(b).blockchain_branch);
        if (mm_tag.depth != b.blockchain_branch.size())
          return false;
        for (size_t i = 0; i < mm_tag.depth; ++i)
        {
          FIELDS(b.blockchain_branch[i]);
          if (i + 1 < mm_tag.depth)
            ar.delimit_array();
        }
        ar.end_array();
      }
    END_SERIALIZE()
  };

  // Implemented below
  inline serializable_bytecoin_block make_serializable_bytecoin_block(const block& b, bool hashing_serialization, bool header_only);

  struct block_header
  {
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash prev_id;
    uint32_t nonce;

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      if(major_version > BLOCK_MAJOR_VERSION_2) return false;
      VARINT_FIELD(minor_version)
      if (BLOCK_MAJOR_VERSION_1 == major_version)
      {
        VARINT_FIELD(timestamp)
      }
      FIELD(prev_id)
      if (BLOCK_MAJOR_VERSION_1 == major_version)
      {
        FIELD(nonce)
      }
    END_SERIALIZE()
  };

  struct block: public block_header
  {
    bytecoin_block parent_block;

    transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<block_header *>(this))
      if (BLOCK_MAJOR_VERSION_2 <= major_version)
      {
        auto sbb = make_serializable_bytecoin_block(*this, false, false);
        FIELD_N("parent_block", sbb);
      }
      FIELD(miner_tx)
      FIELD(tx_hashes)
    END_SERIALIZE()
  };

  inline serializable_bytecoin_block make_serializable_bytecoin_block(const block& b, bool hashing_serialization, bool header_only)
  {
    block& block_ref = const_cast<block&>(b);
    return serializable_bytecoin_block(block_ref.parent_block, block_ref.timestamp, hashing_serialization, header_only);
  }


  struct bb_block_header
  {
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint64_t nonce;
    uint8_t flags;

    BEGIN_SERIALIZE()
      FIELD(major_version)
      FIELD(nonce)
      FIELD(prev_id)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(flags)
    END_SERIALIZE()
  };

  struct bb_block: public bb_block_header
  {
    bb_transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;

    BEGIN_SERIALIZE()
      FIELDS(*static_cast<bb_block_header *>(this))
      FIELD(miner_tx)
      FIELD(tx_hashes)
    END_SERIALIZE()
  };

    struct lui_block_header
  {
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint64_t nonce;
    uint8_t flags;

    BEGIN_SERIALIZE()
      FIELD(major_version)
      if(major_version > CURRENT_BLOCK_MAJOR_VERSION) return false;
      FIELD(nonce)
      FIELD(prev_id)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(flags)
    END_SERIALIZE()
  };

  struct lui_block: public lui_block_header
  {
    lui_transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;
    crypto::signature pos_sig;
    
    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<lui_block_header *>(this))
      FIELD(miner_tx)
      FIELD(tx_hashes)
      if (this->flags&CURRENCY_BLOCK_FLAG_POS_BLOCK)
      {
        FIELD(pos_sig)
      }
    END_SERIALIZE()
  };



  struct keypair
  {
    crypto::public_key pub;
    crypto::secret_key sec;

    static inline keypair generate()
    {
      keypair k;
      generate_keys(k.pub, k.sec);
      return k;
    }
  };
  //---------------------------------------------------------------
  //PoS
  //based from ppcoin/novacoin approach

  /*
  POS PROTOCOL, stake modifier


  */


  struct offer_details_ex : public cryptonote::offer_details
  {
    std::string tx_hash;
    uint64_t index_in_tx;
    uint64_t timestamp;        //this is not kept by transaction, info filled by corresponding transaction
    uint64_t fee;              //value of fee to pay(or paid in case of existing offers) to rank it
    bool stopped;              //value of fee to pay(or paid in case of existing offers) to rank it

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(offer_type)
      KV_SERIALIZE(amount_lui)
      KV_SERIALIZE(amount_etc)
      KV_SERIALIZE(bonus)
      KV_SERIALIZE(target)
      KV_SERIALIZE(location_country)
      KV_SERIALIZE(location_city)
      KV_SERIALIZE(contacts)
      KV_SERIALIZE(comment)
      KV_SERIALIZE(payment_types)
      KV_SERIALIZE(expiration_time)
      KV_SERIALIZE(tx_hash)
      KV_SERIALIZE(index_in_tx)
      KV_SERIALIZE(timestamp)
      KV_SERIALIZE(fee)
    END_KV_SERIALIZE_MAP()
  };

#pragma pack(push, 1)
  struct stake_modifier_type
  {
    crypto::hash last_pow_id;
    crypto::hash last_pos_kernel_id;
  };

  struct stake_kernel
  {
    stake_modifier_type stake_modifier;
    uint64_t block_timestamp;             //this block timestamp
    crypto::key_image kimage;
  };
#pragma pack(pop)

  struct pos_entry
  {
    uint64_t amount;
    uint64_t index;
    crypto::key_image keyimage;
    uint64_t block_timestamp;
    //not for serialization
    uint64_t wallet_index;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(amount)
      KV_SERIALIZE(index)
      KV_SERIALIZE(block_timestamp)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(keyimage)
    END_KV_SERIALIZE_MAP()
  };
}

BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::bb_txout_to_key);
BLOB_SERIALIZER(cryptonote::lui_txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

VARIANT_TAG(binary_archive, cryptonote::txin_gen, 0xff);
VARIANT_TAG(binary_archive, cryptonote::txin_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txin_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txin_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txout_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txout_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::bb_txout_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::lui_txout_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::transaction, 0xcc);
VARIANT_TAG(binary_archive, cryptonote::block, 0xbb);

VARIANT_TAG(binary_archive, cryptonote::offer_details, 0x0);
VARIANT_TAG(binary_archive, cryptonote::tx_comment, 0x1);
VARIANT_TAG(binary_archive, cryptonote::tx_payer, 0x2);
VARIANT_TAG(binary_archive, std::string, 0x3);
VARIANT_TAG(binary_archive, cryptonote::tx_crypto_checksum, 0x4);
VARIANT_TAG(binary_archive, cryptonote::tx_message, 0x5);
VARIANT_TAG(binary_archive, cryptonote::cancel_offer, 0x6);




VARIANT_TAG(binary_archive, cryptonote::extra_attachment_info, 0x0);
VARIANT_TAG(binary_archive, cryptonote::extra_user_data, 0x1);
VARIANT_TAG(binary_archive, cryptonote::extra_alias_entry, 0x2);
VARIANT_TAG(binary_archive, cryptonote::extra_padding, 0x3);
VARIANT_TAG(binary_archive, crypto::public_key, 0x4);

VARIANT_TAG(json_archive, cryptonote::txin_gen, "gen");
VARIANT_TAG(json_archive, cryptonote::txin_to_script, "script");
VARIANT_TAG(json_archive, cryptonote::txin_to_scripthash, "scripthash");
VARIANT_TAG(json_archive, cryptonote::txin_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::txout_to_script, "script");
VARIANT_TAG(json_archive, cryptonote::txout_to_scripthash, "scripthash");
VARIANT_TAG(json_archive, cryptonote::txout_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::bb_txout_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::lui_txout_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::transaction, "tx");
VARIANT_TAG(json_archive, cryptonote::block, "block");

VARIANT_TAG(json_archive, cryptonote::offer_details, "offer");
VARIANT_TAG(json_archive, cryptonote::tx_comment, "comment");
VARIANT_TAG(json_archive, cryptonote::tx_payer, "payer");
VARIANT_TAG(json_archive, std::string, "string");
VARIANT_TAG(json_archive, crypto::public_key, "pub_key");
VARIANT_TAG(json_archive, cryptonote::tx_crypto_checksum, "check_summ");
VARIANT_TAG(json_archive, cryptonote::tx_message, "message");
VARIANT_TAG(json_archive, cryptonote::cancel_offer, "canscel_offer");




VARIANT_TAG(json_archive, cryptonote::extra_attachment_info, "attachment");
VARIANT_TAG(json_archive, cryptonote::extra_user_data, "user_data");
VARIANT_TAG(json_archive, cryptonote::extra_alias_entry, "alias");
VARIANT_TAG(json_archive, cryptonote::extra_padding, "padding");

VARIANT_TAG(debug_archive, cryptonote::txin_gen, "gen");
VARIANT_TAG(debug_archive, cryptonote::txin_to_script, "script");
VARIANT_TAG(debug_archive, cryptonote::txin_to_scripthash, "scripthash");
VARIANT_TAG(debug_archive, cryptonote::txin_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::txout_to_script, "script");
VARIANT_TAG(debug_archive, cryptonote::txout_to_scripthash, "scripthash");
VARIANT_TAG(debug_archive, cryptonote::txout_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::bb_txout_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::lui_txout_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::transaction, "tx");
VARIANT_TAG(debug_archive, cryptonote::block, "block");


VARIANT_TAG(debug_archive, cryptonote::offer_details, "offer");
VARIANT_TAG(debug_archive, cryptonote::tx_comment, "comment");
VARIANT_TAG(debug_archive, cryptonote::tx_payer, "payer");
VARIANT_TAG(debug_archive, std::string, "string");
//VARIANT_TAG(debug_archive, crypto::public_key, "pub_key");


VARIANT_TAG(debug_archive, cryptonote::extra_attachment_info, "attachment");
VARIANT_TAG(debug_archive, cryptonote::extra_user_data, "user_data");
VARIANT_TAG(debug_archive, cryptonote::extra_alias_entry, "alias");
VARIANT_TAG(debug_archive, cryptonote::extra_padding, "padding");
VARIANT_TAG(debug_archive, cryptonote::cancel_offer, "cancel_offer");