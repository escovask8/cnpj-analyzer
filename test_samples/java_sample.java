package com.example.cnpjanalyzer.test;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.regex.Pattern;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.stereotype.Service;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

/**
 * This file contains various CNPJ usage patterns for testing the CNPJ analyzer.
 * It includes examples of string literals, numeric literals, conversions,
 * sanitization, validation, and database operations.
 */

// Entity example
@Entity
public class Company {
    
    @Id
    private Long id;
    
    // String with mask annotation
    @Column(name = "CNPJ", length = 18)
    private String cnpj;
    
    // Numeric CNPJ field
    @Column(name = "CNPJ_NUMERIC")
    private Long cnpjNumeric;
    
    // Getters and setters
    public String getCnpj() {
        return cnpj;
    }
    
    public void setCnpj(String cnpj) {
        // Validation before setting
        if (isValidCNPJ(cnpj)) {
            this.cnpj = cnpj;
        } else {
            throw new IllegalArgumentException("Invalid CNPJ format");
        }
    }
    
    public Long getCnpjNumeric() {
        return cnpjNumeric;
    }
    
    public void setCnpjNumeric(Long cnpjNumeric) {
        this.cnpjNumeric = cnpjNumeric;
    }
    
    // CNPJ validation method
    private boolean isValidCNPJ(String cnpj) {
        // Remove non-digits
        String digits = cnpj.replaceAll("\\D", "");
        
        // Check length
        if (digits.length() != 14) {
            return false;
        }
        
        // Check for repeated digits
        if (digits.matches("(\\d)\\1{13}")) {
            return false;
        }
        
        // Calculate verification digits (simplified)
        int sum = 0;
        int weight = 2;
        for (int i = 11; i >= 0; i--) {
            sum += (digits.charAt(i) - '0') * weight;
            weight = weight == 9 ? 2 : weight + 1;
        }
        
        int remainder = sum % 11;
        int digit1 = remainder < 2 ? 0 : 11 - remainder;
        
        if (digit1 != (digits.charAt(12) - '0')) {
            return false;
        }
        
        sum = 0;
        weight = 2;
        for (int i = 12; i >= 0; i--) {
            sum += (digits.charAt(i) - '0') * weight;
            weight = weight == 9 ? 2 : weight + 1;
        }
        
        remainder = sum % 11;
        int digit2 = remainder < 2 ? 0 : 11 - remainder;
        
        return digit2 == (digits.charAt(13) - '0');
    }
    
    // Format CNPJ method
    public String formatCNPJ() {
        if (cnpj == null) {
            return null;
        }
        
        String digits = cnpj.replaceAll("\\D", "");
        if (digits.length() != 14) {
            return cnpj;
        }
        
        return String.format("%s.%s.%s/%s-%s",
                digits.substring(0, 2),
                digits.substring(2, 5),
                digits.substring(5, 8),
                digits.substring(8, 12),
                digits.substring(12));
    }
    
    // Convert CNPJ to numeric
    public void convertCNPJToNumeric() {
        if (cnpj != null) {
            String digits = cnpj.replaceAll("\\D", "");
            this.cnpjNumeric = Long.parseLong(digits);
        }
    }
}

// Repository example
@org.springframework.stereotype.Repository
public interface CompanyRepository extends JpaRepository<Company, Long> {
    
    // Find by CNPJ
    Company findByCnpj(String cnpj);
    
    // Custom query with CNPJ
    @Query("SELECT c FROM Company c WHERE c.cnpj = :cnpj")
    Company findCompanyByCNPJ(@org.springframework.data.repository.query.Param("cnpj") String cnpj);
    
    // Find by numeric CNPJ
    Company findByCnpjNumeric(Long cnpjNumeric);
}

// Service example
@Service
public class CompanyService {
    
    private final CompanyRepository companyRepository;
    
    // Constructor injection
    public CompanyService(CompanyRepository companyRepository) {
        this.companyRepository = companyRepository;
    }
    
    // Validate and save company
    public Company saveCompany(Company company) {
        // Sanitize CNPJ
        String sanitizedCnpj = sanitizeCNPJ(company.getCnpj());
        company.setCnpj(formatCNPJ(sanitizedCnpj));
        
        // Convert to numeric
        company.setCnpjNumeric(Long.valueOf(sanitizedCnpj));
        
        return companyRepository.save(company);
    }
    
    // Find company by CNPJ
    public Company findByCNPJ(String cnpj) {
        String sanitized = sanitizeCNPJ(cnpj);
        String formatted = formatCNPJ(sanitized);
        return companyRepository.findByCnpj(formatted);
    }
    
    // Sanitize CNPJ (remove non-digits)
    private String sanitizeCNPJ(String cnpj) {
        if (cnpj == null) {
            return null;
        }
        return cnpj.replaceAll("\\D", "");
    }
    
    // Format CNPJ with mask
    private String formatCNPJ(String digits) {
        if (digits == null || digits.length() != 14) {
            return digits;
        }
        
        return new DecimalFormat("00.000.000/0000-00").format(
                new BigInteger(digits));
    }
    
    // Validate CNPJ
    public boolean validateCNPJ(String cnpj) {
        // CNPJ pattern with mask
        Pattern pattern = Pattern.compile("\\d{2}\\.\\d{3}\\.\\d{3}/\\d{4}-\\d{2}");
        
        // Check format first
        if (!pattern.matcher(cnpj).matches()) {
            return false;
        }
        
        // Then check algorithm (simplified)
        String digits = sanitizeCNPJ(cnpj);
        
        // Check for repeated digits
        if (digits.matches("(\\d)\\1{13}")) {
            return false;
        }
        
        // Simplified validation logic
        return digits.length() == 14;
    }
}

// Controller example
@RestController
@RequestMapping("/api/companies")
public class CompanyController {
    
    private final CompanyService companyService;
    
    // Constructor injection
    public CompanyController(CompanyService companyService) {
        this.companyService = companyService;
    }
    
    // Get company by CNPJ
    @RequestMapping("/find")
    public Company findCompany(@RequestParam("cnpj") String cnpj) {
        // Validate input
        if (!companyService.validateCNPJ(cnpj)) {
            throw new IllegalArgumentException("Invalid CNPJ format");
        }
        
        return companyService.findByCNPJ(cnpj);
    }
    
    // Create company
    @RequestMapping("/create")
    public Company createCompany(@RequestParam("name") String name, 
                                @RequestParam("cnpj") String cnpj) {
        // Example CNPJ for testing: "12.345.678/0001-95"
        Company company = new Company();
        company.setCnpj(cnpj);
        
        return companyService.saveCompany(company);
    }
}

// SQL example (as a comment)
/*
CREATE TABLE company (
    id BIGINT PRIMARY KEY,
    CNPJ VARCHAR(18) NOT NULL UNIQUE,
    CNPJ_NUMERIC BIGINT NOT NULL
);

INSERT INTO company (id, CNPJ, CNPJ_NUMERIC) 
VALUES (1, '12.345.678/0001-95', 12345678000195);

SELECT * FROM company WHERE CNPJ = '12.345.678/0001-95';
*/

// Example with Brazilian company tax ID synonym
class TaxIdentification {
    // Brazilian company tax ID (CNPJ)
    private String brazilianCompanyTaxId;
    
    // 14-digit company identifier
    private String companyIdentifier;
    
    // Cadastro Nacional da Pessoa Jurídica
    private String cadastroNacionalDaPessoaJuridica;
    
    public void setIdentifiers(String cnpj) {
        this.brazilianCompanyTaxId = cnpj;
        this.companyIdentifier = cnpj.replaceAll("\\D", "");
        this.cadastroNacionalDaPessoaJuridica = cnpj;
    }
}