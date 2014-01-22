/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package minipgp;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author leonardo
 */
public class RSAKeyMethods {
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException{
        return KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }
}
