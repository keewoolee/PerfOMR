#include "PVWToBFVSeal.h"
#include "SealUtils.h"
#include "retrieval.h"
#include "client.h"
#include "LoadAndSaveUtils.h"
#include "OMRUtil.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

// OMD variant of serverOperations3therest_obliviousExpansion_time:
// Only performs randomized index retrieval (LHS). No payload packing (RHS).
void OMD_serverOperations3therest_obliviousExpansion_time(EncryptionParameters& enc_param, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map,
                                                 vector<vector<Ciphertext>>& rhs, Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload,
                                                 const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const SecretKey& secretKey,
                                                 const PublicKey& public_key, const size_t& degree, const SEALContext& context_next,
                                                 const SEALContext& context_expand, const int numOfTransactions, int& counter, uint64_t& unpack_pv_time,
                                                 uint64_t& digest_encode_time, int numberOfCt = 1, int partySize = 1, int slotPerBucket = 3,
                                                 bool concate = false, const int payloadSize = 306, const int t = 65537) {

    Evaluator evaluator(context_expand);
    Decryptor decryptor(context_expand, secretKey);

    chrono::high_resolution_clock::time_point s1, e1;
    uint64_t t1 = 0;

    int step = step_size_glb, k = 0;

    s1 = chrono::high_resolution_clock::now();
    vector<Ciphertext> expanded_subtree_leaves = subExpand(secretKey, context_expand, enc_param, packedSIC, poly_modulus_degree_glb, gal_keys, poly_modulus_degree_glb/step);
    e1 = chrono::high_resolution_clock::now();
    t1 += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
    vector<Ciphertext> partial_expandedSIC(step);

    for (int i = counter; i < counter+numOfTransactions; i += step) {
        // step 1. expand PV
        s1 = chrono::high_resolution_clock::now();
        partial_expandedSIC = expand(context_expand, enc_param, expanded_subtree_leaves[k], poly_modulus_degree_glb, gal_keys, step);

        for(size_t j = 0; j < partial_expandedSIC.size(); j++) {
            if(!partial_expandedSIC[j].is_ntt_form()) {
                evaluator.transform_to_ntt_inplace(partial_expandedSIC[j]);
            }
        }

        e1 = chrono::high_resolution_clock::now();
        t1 += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();

        // step 2. randomized retrieval (LHS only, no payload)
        randomizedIndexRetrieval_opt(lhsCounter, partial_expandedSIC, context_next, public_key, i, degree,
                                     repetition_glb, numberOfCt, num_bucket_glb, partySize, slotPerBucket,
                                     step_size_glb, k);
        k++;
    }

    for(size_t i = 0; i < lhsCounter.size(); i++){
            evaluator.transform_from_ntt_inplace(lhsCounter[i]);
    }

    counter += numOfTransactions;

    unpack_pv_time += t1;
}

// OMD variant of decoding: extracts pertinent message indices directly (no payload recovery).
void OMD_decodeIndicesRandom_opt(vector<int>& pertinentIndices, const vector<Ciphertext>& buckets, const SecretKey& secret_key,
                             const SEALContext& context, int partySize = 1, size_t slots_per_bucket = 3){
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    int detectedSum = 0;
    int pvSumOfPertinentMsg = 0;
    vector<uint64_t> countertemp(poly_modulus_degree_glb);
    Plaintext plain_result;
    decryptor.decrypt(buckets[0], plain_result);
    batch_encoder.decode(plain_result, countertemp);
    for(int i = (slots_per_bucket - 1) * num_bucket_glb; i < (int) slots_per_bucket * num_bucket_glb; i++){
        pvSumOfPertinentMsg += countertemp[i]; // first sum up the pv_values for all pertinent messages
    }

    for(int i = 0; i < (int) buckets.size(); i++){ // iterate through all ciphertexts
        vector<uint64_t> plain_bucket(poly_modulus_degree_glb);
        decryptor.decrypt(buckets[i], plain_result);
        batch_encoder.decode(plain_result, plain_bucket);

        for(int j = 0; j < (int) (poly_modulus_degree_glb / num_bucket_glb / slots_per_bucket); j++){ // iterate through all repetitions encryted in one ciphertext
            for(int k = 0; k < num_bucket_glb; k++) { // iterate through all buckets in one repetition
                uint64_t pv_value = plain_bucket[j * slots_per_bucket * num_bucket_glb + (slots_per_bucket - 1) * num_bucket_glb + k]; // extract the counter value of this bucket
                if ((int) pv_value > partySize) // trivially overflow
                    continue;
                if (pv_value >= 1) {
                    uint128_t index = 0;
                    for (int s = 0; s < (int) (slots_per_bucket-1); s++) {
		                uint64_t curr_slot_value = plain_bucket[j * slots_per_bucket * num_bucket_glb + s * num_bucket_glb + k];
			            curr_slot_value = div_mod((long) curr_slot_value, (long) pv_value, 65537);
                        index = (uint128_t) (index * 65537 + curr_slot_value);
                    }
                    int real_index = extractIndexWithoutCollision(index, partySize, 1);

                    if(real_index != -1 && find(pertinentIndices.begin(), pertinentIndices.end(), real_index) == pertinentIndices.end()){
                        pertinentIndices.push_back(real_index);
                        detectedSum += pv_value;
                    }
                }
                if(detectedSum == pvSumOfPertinentMsg)
                    break;
            }
        }
    }
    sort(pertinentIndices.begin(), pertinentIndices.end());

    if(detectedSum != pvSumOfPertinentMsg)
    {
        cerr << "Overflow: detected pv sum: " << detectedSum << " less than expected: " << pvSumOfPertinentMsg << endl;
        exit(1);
    }
}

void OMD3_opt() {
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    int t = 65537;

    process_u_time.resize(numcores, 0);
    unpack_pv_time.resize(numcores, 0);
    digest_encode_time.resize(numcores, 0);

    int numOfTransactions = numOfTransactions_glb;
    int half_party_size = ceil(((double) party_size_glb) / 2.0);

    OMRthreeM = default_bucket_num_glb * (num_of_pertinent_msgs_glb / 50);
    repeatition_glb = OMRthreeM;

    int payload_size = 306;

    int num_ct_for_buckets = OMRthreeM / default_bucket_num_glb;

    cout << "Preparing database and paramaters...\n";
    createDatabase(numOfTransactions * half_party_size, payload_size*2);

    // step 1. generate OPVW sk
    auto params = OPVWParam(512, 400, 0.5, 6, 32);
    if (default_param_set) {
        params = OPVWParam(1024, 65537, 0.5, 2, 32);
    }

    auto sk = OPVWGenerateSecretKey(params);
    auto pk = OPVWGeneratePublicKey(params, sk);

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal_opt(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb,  params);

    cout << "Pertient message indices: "<< pertinentMsgIndices << endl;

    // step 3. generate detection key
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 60, 28, 60,
                                                                     60, 60, 60, 60,
                                                                     60, 60, 60, 60,
                                                                     60, 60, 60});
    if (default_param_set) {
        coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 60, 55, 60, 60,
                                                                    60, 60, 60, 60,
                                                                    60, 60, 60, 60,
                                                                    60, 60, 22, 60});
    }
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(t);

    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    for (int i = 0; i < params.n; i++) {
        sk[i] = sk[i] == params.q-1 ? 65536 : sk[i];
    }
    Ciphertext switchingKey = omr_take3::generateDetectionKeyForOPVWsk(context, poly_modulus_degree, public_key, secret_key, sk, params);
    for (int i = 0; i < params.n; i++) {
        sk[i] = sk[i] == 65536 ? params.q-1 : sk[i];
    }

    Ciphertext packedSIC;

    vector<vector<OPVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys, gal_keys_slotToCoeff, gal_keys_expand;
    vector<int> stepsfirst = {1};
    keygen.create_galois_keys(stepsfirst, gal_keys);

    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2) {
	    steps.push_back(i);
    }

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);
    Evaluator evaluator_next(context_next);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next);

    vector<int> slotToCoeff_steps_coeff = {0, 1};
    slotToCoeff_steps_coeff.push_back(sqrt(degree/2));
    keygen_next.create_galois_keys(slotToCoeff_steps_coeff, gal_keys_slotToCoeff);

    //////////////////////////////////////////////////////
    vector<Modulus> coeff_modulus_expand = coeff_modulus;
    coeff_modulus_expand.erase(coeff_modulus_expand.begin() + 2, coeff_modulus_expand.end()-1);
    EncryptionParameters parms_expand = parms;
    parms_expand.set_coeff_modulus(coeff_modulus_expand);
    SEALContext context_expand = SEALContext(parms_expand, true, sec_level_type::none);

    SecretKey sk_expand;
    sk_expand.data().resize(coeff_modulus_expand.size() * degree);
    sk_expand.parms_id() = context_expand.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_expand.size() - 1, sk_expand.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_expand.data().data() + degree * (coeff_modulus_expand.size() - 1));
    KeyGenerator keygen_expand(context_expand, sk_expand);
    vector<uint32_t> galois_elts;
    auto n = poly_modulus_degree;
    for (int i = 0; i < ceil(log2(poly_modulus_degree)); i++) {
        galois_elts.push_back((n + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }
    keygen_expand.create_galois_keys(galois_elts, gal_keys_expand);

    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);

    stringstream data_streamkey;
    int keysize = 0;
    keysize += relin_keys.save(data_streamkey);
    keysize += gal_keys.save(data_streamkey);
    keysize += gal_keys_slotToCoeff.save(data_streamkey);
    keysize += gal_keys_expand.save(data_streamkey);
    keysize += switchingKey.save(data_streamkey);
    cout << "Detection key size: " << keysize / 1000000 << "MB" << endl;

    cout << "Database and parameters prepared.\n\n";

    ////////////////////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree));

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end, s,e;
    chrono::microseconds time_diff;

    Plaintext pl;
    vector<uint64_t> tm(poly_modulus_degree);

    int tempn;
    for(tempn = 1; tempn < params.n; tempn*=2) {}
    vector<Ciphertext> rotated_switchingKey;

    {
    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

    rotated_switchingKey.resize(tempn);
    s = chrono::high_resolution_clock::now();
    rotated_switchingKey[0] = switchingKey;
    for(int i = 1; i < tempn; i++){
        evaluator.rotate_rows(rotated_switchingKey[i-1], 1, gal_keys, rotated_switchingKey[i]);
    }
    for (int i = 0; i < tempn; i++) {
        evaluator.transform_to_ntt_inplace(rotated_switchingKey[i]);
    }
    e = chrono::high_resolution_clock::now();
    total_affine_us += chrono::duration_cast<chrono::microseconds>(e - s).count();

    time_start = chrono::high_resolution_clock::now();

    NTL_EXEC_RANGE(numcores, first, last);
    chrono::high_resolution_clock::time_point s1, e1;
    uint64_t t11 = 0, t22 = 0, bb_to_pv = 0;
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree) {

            Ciphertext packedSIC_temp;
            s1 = chrono::high_resolution_clock::now();
            for (int p = 0; p < party_size_glb; p++) {

	        s = chrono::high_resolution_clock::now();
                loadClues_OPVW(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params, p, party_size_glb);
		e = chrono::high_resolution_clock::now();
		t11 += chrono::duration_cast<chrono::microseconds>(e - s).count();
		total_affine_us += chrono::duration_cast<chrono::microseconds>(e - s).count();

		s = chrono::high_resolution_clock::now();
                packedSIC_temp = obtainPackedSICFromRingLWEClue(secret_key, SICPVW_multicore[i], rotated_switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree, default_param_set);

                if (p == 0){
                    packedSICfromPhase1[i][j] = packedSIC_temp;
                } else {
                    evaluator.add_inplace(packedSICfromPhase1[i][j], packedSIC_temp);
                }
		e = chrono::high_resolution_clock::now();
		t22 += chrono::duration_cast<chrono::microseconds>(e - s).count();
            }
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
            e1 = chrono::high_resolution_clock::now();
	    bb_to_pv += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
        }
    }

    NTL_EXEC_RANGE_END;
    for (int i = 0; i < tempn; i++) {
        rotated_switchingKey[i].release();
    }
    MemoryManager::SwitchProfile(std::move(old_prof));
    }
    rotated_switchingKey.clear();

    cout << "Affine time: " << ((double) total_affine_us) / 1000000 << "sec" << endl;
    cout << "RangeCheck time: " << ((double) total_rangecheck_us) / 1000000 << "sec" << endl;

    // step 4. detector operations (OMD: LHS only, no RHS)
    chrono::high_resolution_clock::time_point compress_start = chrono::high_resolution_clock::now();
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    int encode_bit = ceil(log2(party_size_glb + 1));
    int index_bit = log2(numOfTransactions_glb);
    int acc_slots = ceil(encode_bit * index_bit / (16.0));
    int number_of_ct = ceil(repetition_glb * (acc_slots+1) * num_bucket_glb / ((poly_modulus_degree_glb / num_bucket_glb / (acc_slots+1) * (acc_slots+1) * num_bucket_glb) * 1.0));

    uint64_t inv = modInverse(degree, t);

    int sq_ct = sqrt(degree/2);

    NTL_EXEC_RANGE(numcores, first, last);
    chrono::high_resolution_clock::time_point s1, e1;
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;
        vector<Ciphertext> packSIC_sqrt_list(2*sq_ct);

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
            loadPackedData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree, payload_size*2, half_party_size);
            vector<Ciphertext> templhsctr;
	    vector<vector<Ciphertext>> temprhs(num_ct_for_buckets);
	    for (int c = 0; c < (int) num_ct_for_buckets; c++) {
	      temprhs[c].resize(half_party_size);
	    }

            Ciphertext curr_PackSIC(packedSICfromPhase1[i][j]);
            s1 = chrono::high_resolution_clock::now();
            Ciphertext packSIC_copy(curr_PackSIC);
            evaluator_next.rotate_columns_inplace(packSIC_copy, gal_keys_slotToCoeff);

            packSIC_sqrt_list[0] = curr_PackSIC;
            packSIC_sqrt_list[sq_ct] = packSIC_copy;

            for (int c = 1; c < sq_ct; c++) {
                evaluator_next.rotate_rows(packSIC_sqrt_list[c-1], sq_ct, gal_keys_slotToCoeff, packSIC_sqrt_list[c]);
                evaluator_next.rotate_rows(packSIC_sqrt_list[c-1+sq_ct], sq_ct, gal_keys_slotToCoeff, packSIC_sqrt_list[c+sq_ct]);
            }
            for (int c = 0; c < sq_ct; c++) {
                evaluator_next.transform_to_ntt_inplace(packSIC_sqrt_list[c]);
                evaluator_next.transform_to_ntt_inplace(packSIC_sqrt_list[c+sq_ct]);
            }

            Ciphertext packSIC_coeff = slotToCoeff_WOPrepreocess_time(context, context_next, packSIC_sqrt_list,
								      gal_keys_slotToCoeff, process_u_time[i], 128, degree, t, inv);

	    e1 = chrono::high_resolution_clock::now();
	    unpack_pv_time[i] += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
            if (!default_param_set) {
                evaluator.mod_switch_to_next_inplace(packSIC_coeff);
            }

            OMD_serverOperations3therest_obliviousExpansion_time(parms_expand, templhsctr, bipartite_map[i], temprhs, packSIC_coeff, payload_multicore[i],
							     relin_keys, gal_keys_expand, sk_expand, public_key_last, poly_modulus_degree, context_next, context_expand,
							     poly_modulus_degree, counter[i], unpack_pv_time[i], digest_encode_time[i], number_of_ct, party_size_glb,
		    					     acc_slots+1, true);

            if(j == 0){
                lhs_multi_ctr[i] = templhsctr;
            } else {
                for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
    }

    uint64_t total_u = 0, total_unpack = 0, total_digest = 0;
    for (int i = 0; i < numcores; i++) {
      total_u += process_u_time[i];
      total_unpack += unpack_pv_time[i];
      total_digest += digest_encode_time[i];
    }

    while(context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()) {
        for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
            evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
        }
    }

    //////////// for compact digest, mod the ciphertext to smaller q (60 --> 28 bit) and then return ////////////
    //////////// so recipient decrypts using a smaller key, and the BFV evaluation use the large key ////////////
    EncryptionParameters bfv_params_small(scheme_type::bfv);
    bfv_params_small.set_poly_modulus_degree(degree);
    auto coeff_modulus_small = CoeffModulus::Create(degree, { 28, 60});
    bfv_params_small.set_coeff_modulus(coeff_modulus_small);
    bfv_params_small.set_plain_modulus(t);

    bfv_params_small.set_random_generator(rng);
    SEALContext seal_context_small(bfv_params_small, true, sec_level_type::none);
    KeyGenerator keygen_small(seal_context_small);

    SecretKey secret_key_small = keygen_small.secret_key();

    uint64_t small_p = 268369920;
    uint64_t large_p = 281474976317440;
    inverse_ntt_negacyclic_harvey(secret_key.data().data(), context.key_context_data()->small_ntt_tables()[0]);
    for (int i = 0; i < params.n; i++) {
        if (secret_key.data()[i] > 1) {
            large_p = (uint64_t) secret_key.data()[i];
	    break;
	}
    }
    seal::util::RNSIter new_key_rns(secret_key.data().data(), degree);
    ntt_negacyclic_harvey(new_key_rns, coeff_modulus.size(), context.key_context_data()->small_ntt_tables());

    inverse_ntt_negacyclic_harvey(secret_key_small.data().data(), seal_context_small.key_context_data()->small_ntt_tables()[0]);
    for (int i = 0; i < params.n; i++) {
        if (secret_key_small.data()[i] > 1) {
            small_p = (uint64_t) secret_key_small.data()[i];
	    break;
	}
    }
    seal::util::RNSIter new_key_rns_small(secret_key_small.data().data(), degree);
    ntt_negacyclic_harvey(new_key_rns_small, coeff_modulus_small.size(), seal_context_small.key_context_data()->small_ntt_tables());


    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint32_t> dist(0, 100);

    // OMD: only LHS mod-down (no RHS)
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
        for (int i = 0; i < (int) degree; i++) {
            lhs_multi_ctr[0][q].data(0)[i] = manual_mod_down_rounding(lhs_multi_ctr[0][q].data(0)[i], dist(engine), small_p+1, large_p+1);
	    lhs_multi_ctr[0][q].data(1)[i] = manual_mod_down_rounding(lhs_multi_ctr[0][q].data(1)[i], dist(engine), small_p+1, large_p+1);
        }
	lhs_multi_ctr[0][q].parms_id_ = seal_context_small.first_parms_id();

    }

    //////////// After generating a default small key, we make it aligned with the large key ////////////
    //////////// such that they differ only w.r.t. the modulus                               ////////////

    inverse_ntt_negacyclic_harvey(secret_key.data().data(), context.key_context_data()->small_ntt_tables()[0]);
    inverse_ntt_negacyclic_harvey(secret_key_small.data().data(), seal_context_small.key_context_data()->small_ntt_tables()[0]);
    for (int i = 0; i < (int) degree; i++) {
      secret_key_small.data()[i] = (secret_key.data()[i] == large_p) ? small_p : secret_key.data()[i];
    }

    seal::util::RNSIter new_key_rns1(secret_key.data().data(), degree);
    ntt_negacyclic_harvey(new_key_rns1, coeff_modulus.size(), context.key_context_data()->small_ntt_tables());
    seal::util::RNSIter new_key_rns_small1(secret_key_small.data().data(), degree);
    ntt_negacyclic_harvey(new_key_rns_small1, coeff_modulus_small.size(), seal_context_small.key_context_data()->small_ntt_tables());

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    chrono::high_resolution_clock::time_point compress_end = chrono::high_resolution_clock::now();
    uint64_t compress_us = chrono::duration_cast<chrono::microseconds>(compress_end - compress_start).count();
    cout << "Preprocessing time: " << ((double) total_u) / 1000000 << "sec" << endl;
    cout << "Compression time: " << ((double)(compress_us - total_u)) / 1000000 << "sec" << endl;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);

    // OMD digest: LHS only
    stringstream data_streamdg2;
    auto digsize = 0;
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize / 1000 << "KB" << endl;

    // step 5. receiver decoding (OMD: index-only decoding)
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();

    vector<int> pertinentIdx;
    OMD_decodeIndicesRandom_opt(pertinentIdx, lhs_multi_ctr[0], secret_key_small, seal_context_small, party_size_glb, acc_slots+1);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Decode time: " << chrono::duration<double, milli>(time_end - time_start).count() << "ms" << endl;

    // Verify correctness
    bool correct = (pertinentIdx.size() == pertinentMsgIndices.size());
    if (correct) {
        for(size_t i = 0; i < pertinentIdx.size(); i++) {
            if(pertinentIdx[i] != pertinentMsgIndices[i]) {
                correct = false;
                break;
            }
        }
    }
    if(correct)
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}
