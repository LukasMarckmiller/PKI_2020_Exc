package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 29.04.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task5.Task5;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        var task = new Task5();
        task.mainTask();
    }
}
