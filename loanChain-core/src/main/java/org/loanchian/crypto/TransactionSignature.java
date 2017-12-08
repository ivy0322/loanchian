package org.loanchian.crypto;

import org.loanchian.core.exception.VerificationException;
import org.loanchian.transaction.Transaction;
import org.loanchian.transaction.Transaction.SigHash;
import org.loanchian.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * A TransactionSignature wraps an {@link org.inchain.crypto.ECKey.ECDSASignature} and adds methods for handling
 * the additional SIGHASH mode byte that is used.
 */
public class TransactionSignature extends ECKey.ECDSASignature {
    public final int sighashFlags;

    /** Constructs a signature with the given components and SIGHASH_ALL. */
    public TransactionSignature(BigInteger r, BigInteger s) {
        this(r, s, Transaction.SigHash.ALL.value);
    }

    /** Constructs a signature with the given components and raw sighash flag bytes (needed for rule compatibility). */
    public TransactionSignature(BigInteger r, BigInteger s, int sighashFlags) {
        super(r, s);
        this.sighashFlags = sighashFlags;
    }

    /** Constructs a transaction signature based on the ECDSA signature. */
    public TransactionSignature(ECKey.ECDSASignature signature, Transaction.SigHash mode) {
        super(signature.r, signature.s);
        sighashFlags = calcSigHashValue(mode);
    }

    public static int calcSigHashValue(Transaction.SigHash mode) {
        Utils.checkState(SigHash.ALL == mode || SigHash.NONE == mode);
        int sighashFlags = mode.value;
        return sighashFlags;
    }

    public Transaction.SigHash sigHashMode() {
        final int mode = sighashFlags & 0x1f;
        if (mode == Transaction.SigHash.NONE.value)
            return Transaction.SigHash.NONE;
        else if (mode == Transaction.SigHash.SING_INPUT.value)
            return Transaction.SigHash.SING_INPUT;
        else
            return Transaction.SigHash.ALL;
    }

    public byte[] encode() {
        try {
            ByteArrayOutputStream bos = derByteStream();
            bos.write(sighashFlags);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static TransactionSignature decode(byte[] bytes) {
    	ECKey.ECDSASignature sig;
        try {
            sig = ECKey.ECDSASignature.decodeFromDER(bytes);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Could not decode DER", e);
        }
        return new TransactionSignature(sig.r, sig.s, bytes[bytes.length - 1]);
	}
	    
    @Override
    public ECKey.ECDSASignature toCanonicalised() {
        return new TransactionSignature(super.toCanonicalised(), sigHashMode());
    }
}
