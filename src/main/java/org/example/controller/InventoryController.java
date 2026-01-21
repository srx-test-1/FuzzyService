package org.example.controller;

import org.example.service.InventoryManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

/**
 * REST controller for inventory management operations.
 */
@RestController
@RequestMapping("/inventory")
public class InventoryController {

    @Autowired
    private InventoryManagementService inventoryService;

    /**
     * Endpoint to build a validated inventory API URL.
     * 
     * @param baseUrl the base URL for the inventory API
     * @param itemId the item ID to look up
     * @return the validated URI as a response
     */
    @GetMapping("/api-url")
    public ResponseEntity<String> getInventoryApiUrl(
            @RequestParam String baseUrl,
            @RequestParam String itemId) {
        try {
            URI validatedUri = inventoryService.buildInventoryApiUrl(baseUrl, itemId);
            return ResponseEntity.ok(validatedUri.toString());
        } catch (IllegalArgumentException e) {
            // Don't expose detailed error messages to prevent information leakage
            return ResponseEntity.badRequest().body("Invalid or untrusted URL");
        }
    }

    /**
     * Endpoint to validate a redirect URL.
     * 
     * @param redirectUrl the URL to validate
     * @return the validated URI or error message
     */
    @GetMapping("/validate-redirect")
    public ResponseEntity<String> validateRedirect(@RequestParam String redirectUrl) {
        try {
            URI validatedUri = inventoryService.validateRedirectUrl(redirectUrl);
            return ResponseEntity.ok("Redirect URL is valid: " + validatedUri.toString());
        } catch (IllegalArgumentException e) {
            // Don't expose detailed error messages to prevent information leakage
            return ResponseEntity.badRequest().body("Invalid or untrusted redirect URL");
        }
    }
}
