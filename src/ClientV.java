import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Random;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ClientV {

    public static void main(String[] args) {

        try {

            // Hier generieren wir einen privaten Schlüssel
            Random rand = new Random();
            BigInteger clientPk = new BigInteger(64, rand);
            System.out.println("Generated private key: " + clientPk);

            // Server Informationen
            String serverHost = "10.13.37.210";
            int port = 2342;

            //zum Server verbinden und seinen public Schlüssel kriegen
            System.out.println("Trying to connect to " + serverHost + ":" + port);
            Socket server = new Socket(serverHost, port);
            System.out.println("connected");
            BufferedReader reader = new BufferedReader(new InputStreamReader(server.getInputStream()));

            System.out.println("public Schlüssel vom Server lautet: " +reader.readLine());

            BigInteger serverPublicKBigInt = new BigInteger(reader.lines().toString().getBytes());
            OutputStream out = server.getOutputStream();

            //generierter privateKey an Server als ByteArray schicken
            //OutputStream out = server.getOutputStream();
            //out.write(clientPk.toByteArray());

            // Diffie-Hellman Algorithm
            BigInteger primeZ = new BigInteger("17948237892432784043");
            BigInteger generator = new BigInteger("5");

            // Sending P als array of Bytes
            //out.write(String.valueOf(primeZ).getBytes(UTF_8));
            // Sending g als array of Bytes
            //out.write(String.valueOf(generator).getBytes(UTF_8));

            // calculation of publicKeyClient = generator exponent privateKey mod primeZahl
            BigInteger publicKeyClient = (generator.modPow(clientPk, primeZ));
            System.out.println("public key von Client = " + publicKeyClient);

            //convert the publicKeyC into a String and the String into a sequence of bytes and returns an array of bytes
            out.write(String.valueOf(publicKeyClient).getBytes(UTF_8)); // Sending publicKeyClient

            // calculation of secret shared Key (gemeinsames Geheimnis)
            BigInteger secretKey = (serverPublicKBigInt.modPow(clientPk, primeZ));
            System.out.println("gemeinsame Geheimnis zur Verschlüsselung = " + secretKey);

            out.flush();

            //One-Time-Pad entschlüsseln
            byte[] oneTimePad = secretKey.toByteArray();
            byte[] msg = reader.lines().toString().getBytes();
            byte[] plainText = new byte[msg.length];

            for (int i = 0; i < oneTimePad.length; i++) {
                plainText[i] = (byte) (((int) msg[i]) ^ ((int) oneTimePad[i % oneTimePad.length]));
            }
             System.out.println("PlainText == " +  new String(plainText));

            System.out.println("Client private Schlüssel in decimal = " +clientPk+ "\n");
            System.out.println("Client private Schlüssel in hexadecimal = " +clientPk.toString(16)+ "\n");

            System.out.println("gemeinsame Geheimnis in decimal = " +secretKey+ "\n");
            System.out.println("gemeinsame Geheimnis in hexadecimal = " +secretKey.toString(16)+ "\n");

            System.out.println("Client public Schlüssel in decimal = " +publicKeyClient+ "\n");
            System.out.println("Client public Schlüssel in hexadecimal = " +publicKeyClient.toString(16)+ "\n");

            System.out.println("Server public Schlüssel in decimal = " +serverPublicKBigInt+ "\n");
            System.out.println("Server public Schlüssel in hexadecimal = "+serverPublicKBigInt.toString(16));

            server.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

