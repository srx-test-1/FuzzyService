package org.example;

import Model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class JacksonCompatibilityTest {

    @Test
    public void testJacksonSerialization() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        User user = new User("John Doe", 30);
        
        // Serialize
        String json = mapper.writeValueAsString(user);
        assertNotNull(json);
        assertTrue(json.contains("John Doe"));
        assertTrue(json.contains("30"));
        
        // Deserialize
        User deserializedUser = mapper.readValue(json, User.class);
        assertNotNull(deserializedUser);
        assertEquals("John Doe", deserializedUser.name);
        assertEquals(30, deserializedUser.age);
    }

    @Test
    public void testDeeplyNestedJson() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        
        // Test that deeply nested JSON doesn't cause StackOverflowError
        // This is the vulnerability that CVE-2020-36518 addresses
        StringBuilder deeplyNested = new StringBuilder();
        int depth = 1000;
        for (int i = 0; i < depth; i++) {
            deeplyNested.append("{\"a\":");
        }
        deeplyNested.append("\"value\"");
        for (int i = 0; i < depth; i++) {
            deeplyNested.append("}");
        }
        
        // With Jackson 2.15.0, this should not throw StackOverflowError
        // It may throw a different exception due to depth limits, which is acceptable
        try {
            mapper.readValue(deeplyNested.toString(), Object.class);
            // If it succeeds, that's fine
        } catch (StackOverflowError e) {
            fail("StackOverflowError should not occur with Jackson 2.15.0");
        } catch (Exception e) {
            // Other exceptions (like depth limit) are acceptable
            // The important thing is we don't get StackOverflowError
            assertTrue(true);
        }
    }
}
