package pgp;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
//
//import sun.misc.BASE64Decoder;

//import sun.misc.BASE64Encoder;
/**
 * Provides methods to encrypt, decrypt, sign and verify signature using PGP keypairs
 */
@Deprecated
public class PGPEncrytionUtil {
/*
    using System;
    using System.IO;
    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Security;

    namespace PgpCrypto
    {
        public class PgpProcessor
        {
            public void SignAndEncryptFile(string actualFileName, string embeddedFileName,
                                           Stream keyIn, long keyId, Stream outputStream,
                                           char[] password, bool armor, bool withIntegrityCheck, PgpPublicKey encKey)
            {
            const int BUFFER_SIZE = 1 << 16; // should always be power of 2

                if (armor)
                    outputStream = new ArmoredOutputStream(outputStream);

                // Init encrypted data generator
                PgpEncryptedDataGenerator encryptedDataGenerator =
                        new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                encryptedDataGenerator.AddMethod(encKey);
                Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte&#91;BUFFER_SIZE&#93;);

                // Init compression
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                Stream compressedOut = compressedDataGenerator.Open(encryptedOut);

                // Init signature
                PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
                PgpSecretKey pgpSecKey = pgpSecBundle.GetSecretKey(keyId);
                if (pgpSecKey == null)
                    throw new ArgumentException(keyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId");
                PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(password);
                PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
                signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);
                foreach (string userId in pgpSecKey.PublicKey.GetUserIds())
                {
                    PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                    spGen.SetSignerUserId(false, userId);
                    signatureGenerator.SetHashedSubpackets(spGen.Generate());
                    // Just the first one!
                    break;
                }
                signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

                // Create the Literal Data generator output stream
                PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                FileInfo embeddedFile = new FileInfo(embeddedFileName);
                FileInfo actualFile = new FileInfo(actualFileName);
                // TODO: Use lastwritetime from source file
                Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary,
                        embeddedFile.Name, actualFile.LastWriteTime, new byte&#91;BUFFER_SIZE&#93;);

                // Open the input file
                FileStream inputStream = actualFile.OpenRead();

                byte&#91;&#93; buf = new byte&#91;BUFFER_SIZE&#93;;
                int len;
                while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
                {
                    literalOut.Write(buf, 0, len);
                    signatureGenerator.Update(buf, 0, len);
                }

                literalOut.Close();
                literalDataGenerator.Close();
                signatureGenerator.Generate().Encode(compressedOut);
                compressedOut.Close();
                compressedDataGenerator.Close();
                encryptedOut.Close();
                encryptedDataGenerator.Close();
                inputStream.Close();

                if (armor)
                    outputStream.Close();
            }
        }
    }*/

    public static byte[] signAndEncrypt(final byte[] message,
                                        final PGPSecretKey secretKey,
                                        final String secretPwd,
                                        final PGPPublicKey publicKey,
                                        final boolean sign,
                                        final boolean encrypt,
                                        final boolean compress,
                                        final boolean converse,
                                        final String encryptType,
                                        final  String filename) throws PGPException {

        try {
            Provider provider = new BouncyCastleProvider();

            OutputStream aux;
            PGPEncryptedDataGenerator encryptedDataGenerator = null;
            PGPCompressedDataGenerator compressedDataGenerator = null;
            PGPSignatureGenerator signatureGenerator = null;

            ByteArrayInputStream in = new ByteArrayInputStream(message);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte bytes[] = message;
            OutputStream compressedOut = null;
            OutputStream encOut = null;
            OutputStream pOut = out;

            if (converse)
                pOut = new ArmoredOutputStream(out);

            if (encrypt == true) {
                int encAlgh = -1;
                if ("AES-128".equals(encryptType))
                    encAlgh = SymmetricKeyAlgorithmTags.AES_128;
                else
                    encAlgh = SymmetricKeyAlgorithmTags.TRIPLE_DES;

                final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(

                        new JcePGPDataEncryptorBuilder( encAlgh).setWithIntegrityPacket( true )
                                .setSecureRandom(
                                        new SecureRandom() )
                                .setProvider( provider ) );
                generator.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( publicKey ).setProvider( provider ) );
                encOut = generator.open(pOut, new byte[1<<16]);
            }
            else
                encOut = pOut;

            if (compress == true) {
                // compression
                compressedDataGenerator =
                        new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
                compressedOut = compressedDataGenerator.open(encOut, new byte[1<<16]);
            }
            else
                compressedOut = encOut;


            if (sign == true) {
                // signing
                final PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider(provider).build(secretPwd.toCharArray()));
                signatureGenerator = new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1)
                                .setProvider(provider));
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
                final Iterator<?> it = secretKey.getPublicKey().getUserIDs();
                if (it.hasNext()) {
                    final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                    spGen.setSignerUserID(false, (String) it.next());
                    signatureGenerator.setHashedSubpackets(spGen.generate());
                }

                signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

            }
            // creating a file stream
            final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

            final OutputStream literalOut = literalDataGenerator
                    .open(compressedOut, PGPLiteralData.BINARY, filename, new Date(), new byte[4096]);

            final byte[] buf = new byte[4096];
            for (int len; (len = in.read(buf)) > 0; ) {
                literalOut.write(buf, 0, len);
                if (sign == true)
                    signatureGenerator.update(buf, 0, len);
            }
            literalOut.close();
            literalDataGenerator.close();
            if (sign == true)
                signatureGenerator.generate().encode(literalOut);
            compressedOut.close();
            if (compress == true)
                compressedDataGenerator.close();
            if(encrypt == true)
                encOut.close();
            if(converse == true)
                pOut.close();

            return ((ByteArrayOutputStream) out).toByteArray();
        } catch (Exception e) {
            System.out.println(e);
        }
        ;
        return null;
    }

    public static void signEncryptMessage(InputStream in, OutputStream out, PGPPublicKey publicKey, PGPPrivateKey secretKey, SecureRandom rand) throws Exception {
        out = new ArmoredOutputStream(out);

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(rand));
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

        OutputStream compressedOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP)
                .open(encryptedDataGenerator.open(out, 4096), new byte[4096]);

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                        new BcPGPContentSignerBuilder(publicKey.getAlgorithm(),
                                HashAlgorithmTags.SHA512));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, secretKey);
        signatureGenerator.generateOnePassVersion(true)
                          .encode(compressedOut);

        OutputStream finalOut = new PGPLiteralDataGenerator()
                            .open(compressedOut, PGPLiteralData.BINARY,
                            "", new Date(), new byte[4096]);

        byte[] buf = new byte[4096];
        int len;
        while ((len = in.read(buf)) > 0) {
            finalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }

        finalOut.close();
        in.close();
        signatureGenerator.generate().encode(compressedOut);
        compressedOut.close();
        encryptedDataGenerator.close();
        out.close();
    }

    public static void decryptVerifyMessage(InputStream in, OutputStream out, PGPPrivateKey secretKey, PGPPublicKey publicKey) throws Exception {
        in = new ArmoredInputStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList enc = (PGPEncryptedDataList) pgpF.nextObject();

        PGPObjectFactory plainFact = new PGPObjectFactory(((PGPPublicKeyEncryptedData) enc.getEncryptedDataObjects().next()).getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(secretKey)), new JcaKeyFingerprintCalculator());

        Object message = null;

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData = null;

        message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            System.out.println(message.toString());
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
                message = plainFact.nextObject();
                System.out.println(message.toString());
            }

            if (message instanceof PGPLiteralData) {
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {

            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                System.out.println("verifier : " + ops.getKeyID());
                if (publicKey != null) {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    ops.update(output);
                    PGPSignature signature = signatureList.get(i);
                    if (ops.verify(signature)) {
                        Iterator<?> userIds = publicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            String userId = (String) userIds.next();
                            System.out.println("Signed by " + userId);
                        }
                        System.out.println("Signature verified");
                    } else {
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }

        }

        out.write(output);
        out.flush();
        out.close();
    }

    public static void main(String args[]) {
        Security.insertProviderAt(new BouncyCastleProvider(), 0);
        byte inBytes[] = "The quick brown fox jumps over the lazy dog.".getBytes();

        try {
            SecureRandom rand = new SecureRandom();

            RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
            kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), rand, 1024, 90));

            BcPGPKeyPair sender = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());
            BcPGPKeyPair recip = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());

            ByteArrayOutputStream sendMessage = new ByteArrayOutputStream();
            ByteArrayOutputStream recvMessage = new ByteArrayOutputStream();
            signEncryptMessage(new ByteArrayInputStream(inBytes), sendMessage, recip.getPublicKey(), sender.getPrivateKey(), rand);

            System.out.println(sendMessage.toString());

            decryptVerifyMessage(new ByteArrayInputStream(sendMessage.toByteArray()), recvMessage, recip.getPrivateKey(), sender.getPublicKey());

            System.out.println(recvMessage.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }//*/
}
