
#include "stratum.h"

static inline uint32_t auxpow_expected_index(uint32_t nonce, int chainid, unsigned h)
{
	// AuxPoW deterministic slot selection.
	// IMPORTANT: must match CAuxPow::getExpectedIndex used by the aux daemon.
	// Reference formula (Namecoin/Lyncoin-style):
	//   r = nonce; r = r*1103515245 + 12345; r += chainid; r = r*1103515245 + 12345; return r % (1<<h);
	const uint32_t mod = (1u << h);
	uint64_t r = (uint64_t)nonce;
	r = r * 1103515245ULL + 12345ULL;
	r += (uint32_t)chainid;
	r = r * 1103515245ULL + 12345ULL;
	return (uint32_t)(r % mod);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void coind_aux_build_auxs(YAAMP_JOB_TEMPLATE *templ)
{
	long long now = current_timestamp();
	int len = 0;
	for(CLI li = g_list_coind.first; li; li = li->next)
	{
		YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
		if(!coind_can_mine(coind, true)) continue;

		// Refresh aux work periodically so parent jobs don't carry stale aux hashes.
		if(coind->last_auxpoll_time == 0 || now - coind->last_auxpoll_time > 10000)
		{
			coind_getauxblock(coind);
			coind->last_auxpoll_time = now;
		}

		// Only include aux chains with valid work.
		if(strlen(coind->aux.hash) < 64 || strlen(coind->aux.target) < 64) continue;
		len++;
	}

	templ->auxs_size = 0;
	memset(templ->auxs, 0, sizeof(templ->auxs));

	if(!len) return;

	// Build a deterministic chain merkle tree.
	// We choose a nonce (templ->aux_nonce) and place each aux chain at the slot
	// determined by CAuxPow::getExpectedIndex(nonce, chainid, merkleHeight).
	for(int h=0; h<MAX_AUXS; h++)
	{
		templ->auxs_size = (int)pow(2, h);
		if(templ->auxs_size < len) continue;

		for(int attempt=0; attempt<100; attempt++)
		{
			uint32_t nonce = (uint32_t)rand();
			memset(templ->auxs, 0, sizeof(templ->auxs));
			bool done = true;

			for(CLI li = g_list_coind.first; li; li = li->next)
			{
				YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
				if(!coind_can_mine(coind, true)) continue;
				if(strlen(coind->aux.hash) < 64 || strlen(coind->aux.target) < 64) continue;

				uint32_t pos = auxpow_expected_index(nonce, coind->aux.chainid, (unsigned)h);
				if(pos >= (uint32_t)templ->auxs_size || templ->auxs[pos])
				{
					done = false;
					break;
				}
				coind->aux.index = (int)pos;
				templ->auxs[pos] = &coind->aux;
			}

			if(done)
			{
				templ->aux_nonce = nonce;
				return;
			}
		}
	}
}

vector<string> coind_aux_hashlist(YAAMP_COIND_AUX **auxs, int size)
{
	vector<string> hashlist;
	for(int i=0; i<size; i++)
	{
		if(auxs[i])
		{
			char hash_be[1024];
			memset(hash_be, 0, 1024);

			if(auxs[i]->hash != NULL)
			{
				string_be(auxs[i]->hash, hash_be);
				hashlist.push_back(hash_be);
			}
		}
		else
			hashlist.push_back("0000000000000000000000000000000000000000000000000000000000000000");
	}

	return hashlist;
}

vector<string> coind_aux_merkle_branch(YAAMP_COIND_AUX **auxs, int size, int index)
{
	vector<string> hashlist = coind_aux_hashlist(auxs, size);
	vector<string> lresult;

	while(hashlist.size() > 1)
	{
		if(index%2)
			lresult.push_back(hashlist[index-1]);
		else
			lresult.push_back(hashlist[index+1]);

		vector<string> l;
		for(int i = 0; i < hashlist.size()/2; i++)
		{
			string s = hashlist[i*2] + hashlist[i*2+1];

			char bin[YAAMP_HASHLEN_BIN*2];
			char out[YAAMP_HASHLEN_STR];

			binlify((unsigned char *)bin, s.c_str());
			sha256_double_hash_hex(bin, out, YAAMP_HASHLEN_BIN*2);

			l.push_back(out);
		}

		hashlist = l;
		index = index/2;
	}

	return lresult;
}




