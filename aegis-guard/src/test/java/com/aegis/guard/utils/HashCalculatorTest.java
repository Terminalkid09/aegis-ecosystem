package com.aegis.guard.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HashCalculatorTest {
    @Test
    void testCalculateHashEmptyPath() {
        HashCalculator calculator = new HashCalculator();
        assertEquals("", calculator.calculateHash(""));
    }

    @Test
    void testCalculateHashNullPath() {
        HashCalculator calculator = new HashCalculator();
        assertEquals("", calculator.calculateHash(null));
    }
}
