package com.example.MorphoAid.DTO.request;

import jakarta.validation.constraints.*;

public class SignupRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 10, message = "Username must be between 3 and 10 characters")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email is invalid")
    @Size(max = 50)
    private String email;

    private String roles;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 20, message = "Password must be between 8 and 20 characters")
    private String password;

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name must not exceed 50 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50, message = "Last name must not exceed 50 characters")
    private String lastName;

    private boolean fromMORU;
    private String invitationToken;

    @NotBlank(message = "Confirm Password is required")
    private String confirmPassword;

    @NotNull(message = "You must agree to the terms and conditions.")
    @AssertTrue(message = "You must agree to the terms and conditions.")
    private Boolean agree;

    // === Getters and Setters ===
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRoles() { return roles; }
    public void setRoles(String roles) { this.roles = roles; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }

    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }

    public boolean isFromMORU() { return fromMORU; }
    public void setFromMORU(boolean fromMORU) { this.fromMORU = fromMORU; }

    public String getInvitationToken() { return invitationToken; }
    public void setInvitationToken(String invitationToken) { this.invitationToken = invitationToken; }

    public String getConfirmPassword() { return confirmPassword; }
    public void setConfirmPassword(String confirmPassword) { this.confirmPassword = confirmPassword; }

    public Boolean getAgree() { return agree; }
    public void setAgree(Boolean agree) { this.agree = agree; }
}
