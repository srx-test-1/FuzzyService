package org.example.controller;

import org.example.service.FuzzyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

/**
 * REST controller for fuzzy search operations.
 */
@RestController
@RequestMapping("/fuzzy")
public class FuzzyController {

    @Autowired
    private FuzzyService fuzzyService;

    /**
     * Endpoint to build a validated fuzzy search URL.
     * 
     * @param apiBaseUrl the base URL for the fuzzy search API
     * @param query the search query
     * @return the validated URI as a response
     */
    @GetMapping("/search-url")
    public ResponseEntity<String> getFuzzySearchUrl(
            @RequestParam String apiBaseUrl,
            @RequestParam String query) {
        try {
            URI validatedUri = fuzzyService.buildFuzzySearchUrl(apiBaseUrl, query);
            return ResponseEntity.ok(validatedUri.toString());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    /**
     * Endpoint to validate a callback URL.
     * 
     * @param callbackUrl the callback URL to validate
     * @return the validated URI or error message
     */
    @GetMapping("/validate-callback")
    public ResponseEntity<String> validateCallback(@RequestParam String callbackUrl) {
        try {
            URI validatedUri = fuzzyService.validateCallbackUrl(callbackUrl);
            return ResponseEntity.ok("Callback URL is valid: " + validatedUri.toString());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }
}
