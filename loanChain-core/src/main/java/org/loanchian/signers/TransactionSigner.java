package org.loanchian.signers;

import org.loanchian.crypto.ECKey;
import org.loanchian.transaction.Transaction;

public interface TransactionSigner {

    boolean isReady();

    byte[] serialize();

    void deserialize(byte[] data);

    boolean signInputs(Transaction tx, ECKey key);
    boolean signOneInputs(Transaction tx, ECKey key, int inputIndex);

}
