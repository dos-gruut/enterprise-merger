#define BOOST_TEST_MODULE

#include <boost/test/unit_test.hpp>
#include <vector>

#include "../../src/services/message_fetcher.hpp"
#include "../../src/services/transaction_fetcher.hpp"
#include "../../src/services/signer_pool_manager.hpp"
#include "../../src/services/signature_requester.hpp"
#include "../../src/chain/transaction.hpp"
#include "../../src/chain/types.hpp"

using namespace gruut;
using namespace std;

BOOST_AUTO_TEST_SUITE(Test_MessageFetcher)

    BOOST_AUTO_TEST_CASE(fetch) {
        auto transaction = MessageFetcher::fetch<Transaction>();
        string type_name = typeid(transaction).name();
        bool result = type_name.find("Transaction") != string::npos;
        BOOST_TEST(result);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(Test_TransactionFetcher)

    BOOST_AUTO_TEST_CASE(fetchAll) {
        vector<Signer> signers;
        Signer signer;
        signer.address = "123";
        signer.cert = "123";

        signers.push_back(signer);
        TransactionFetcher tf(std::move(signers));
        auto transactions = tf.fetchAll();

        auto result = transactions.front().transaction_type == TransactionType::CERTIFICATE;
        BOOST_TEST(result);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(Test_SignerPoolManager)

    BOOST_AUTO_TEST_CASE(getSigners) {
        SignerPoolManager manager;

        auto signers = manager.getSigners();
        BOOST_TEST(signers.size() == 0);

        Signer signer;
        signer.cert = "1234";
        signer.address = "1234";

        manager.putSigner(std::move(signer));

        signers = manager.getSigners();
        BOOST_TEST(signers.size() == 1);
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(Test_SignatureRequester)

    BOOST_AUTO_TEST_CASE(requestSignatures) {
        SignatureRequester requester;

        auto result = requester.requestSignatures();
        BOOST_TEST(result);
    }

BOOST_AUTO_TEST_SUITE_END()