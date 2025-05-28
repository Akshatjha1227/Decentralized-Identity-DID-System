// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title Decentralized Identity (DID) System
 * @dev A smart contract for managing decentralized digital identities
 * @author DID System Team
 */
contract Project {
    
    // Struct to represent a digital identity
    struct Identity {
        string name;
        string email;
        string profileHash; // IPFS hash for additional profile data
        uint256 reputationScore;
        bool isVerified;
        uint256 createdAt;
        uint256 lastUpdated;
    }
    
    // Struct to represent a credential
    struct Credential {
        string credentialType; // e.g., "Education", "Employment", "Certification"
        string issuer;
        string credentialHash; // IPFS hash for credential data
        uint256 issuedAt;
        uint256 expiresAt;
        bool isValid;
    }
    
    // Mappings
    mapping(address => Identity) public identities;
    mapping(address => bool) public hasIdentity;
    mapping(address => Credential[]) public userCredentials;
    mapping(address => bool) public trustedIssuers;
    mapping(address => uint256) public identityCount;
    
    // State variables
    address public owner;
    uint256 public totalIdentities;
    uint256 public constant MAX_REPUTATION_SCORE = 1000;
    
    // Events
    event IdentityCreated(address indexed user, string name, uint256 timestamp);
    event IdentityUpdated(address indexed user, uint256 timestamp);
    event CredentialAdded(address indexed user, string credentialType, string issuer, uint256 timestamp);
    event CredentialRevoked(address indexed user, uint256 credentialIndex, uint256 timestamp);
    event TrustedIssuerAdded(address indexed issuer, uint256 timestamp);
    event TrustedIssuerRemoved(address indexed issuer, uint256 timestamp);
    event ReputationUpdated(address indexed user, uint256 newScore, uint256 timestamp);
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyIdentityOwner(address _user) {
        require(msg.sender == _user, "Only identity owner can perform this action");
        _;
    }
    
    modifier onlyTrustedIssuer() {
        require(trustedIssuers[msg.sender], "Only trusted issuers can perform this action");
        _;
    }
    
    modifier identityExists(address _user) {
        require(hasIdentity[_user], "Identity does not exist");
        _;
    }
    
    // Constructor
    constructor() {
        owner = msg.sender;
        totalIdentities = 0;
        trustedIssuers[msg.sender] = true; // Owner is initially a trusted issuer
    }
    
    /**
     * @dev Core Function 1: Create a new decentralized identity
     * @param _name The name associated with the identity
     * @param _email The email associated with the identity
     * @param _profileHash IPFS hash containing additional profile information
     */
    function createIdentity(
        string memory _name,
        string memory _email,
        string memory _profileHash
    ) public {
        require(!hasIdentity[msg.sender], "Identity already exists for this address");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_email).length > 0, "Email cannot be empty");
        
        identities[msg.sender] = Identity({
            name: _name,
            email: _email,
            profileHash: _profileHash,
            reputationScore: 100, // Starting reputation score
            isVerified: false,
            createdAt: block.timestamp,
            lastUpdated: block.timestamp
        });
        
        hasIdentity[msg.sender] = true;
        totalIdentities++;
        
        emit IdentityCreated(msg.sender, _name, block.timestamp);
    }
    
    /**
     * @dev Core Function 2: Add a credential to a user's identity
     * @param _user The address of the user receiving the credential
     * @param _credentialType The type of credential (e.g., "Education", "Employment")
     * @param _credentialHash IPFS hash containing the credential data
     * @param _expiresAt Expiration timestamp for the credential (0 for no expiration)
     */
    function addCredential(
        address _user,
        string memory _credentialType,
        string memory _credentialHash,
        uint256 _expiresAt
    ) public onlyTrustedIssuer identityExists(_user) {
        require(bytes(_credentialType).length > 0, "Credential type cannot be empty");
        require(bytes(_credentialHash).length > 0, "Credential hash cannot be empty");
        require(_expiresAt == 0 || _expiresAt > block.timestamp, "Invalid expiration time");
        
        // Get issuer information
        string memory issuerName = hasIdentity[msg.sender] ? identities[msg.sender].name : "Unknown Issuer";
        
        Credential memory newCredential = Credential({
            credentialType: _credentialType,
            issuer: issuerName,
            credentialHash: _credentialHash,
            issuedAt: block.timestamp,
            expiresAt: _expiresAt,
            isValid: true
        });
        
        userCredentials[_user].push(newCredential);
        
        // Update reputation score for receiving a credential
        _updateReputationScore(_user, 50);
        
        emit CredentialAdded(_user, _credentialType, issuerName, block.timestamp);
    }
    
    /**
     * @dev Core Function 3: Verify and update identity status
     * @param _user The address of the user to verify
     * @param _verified The verification status to set
     */
    function verifyIdentity(address _user, bool _verified) public onlyTrustedIssuer identityExists(_user) {
        identities[_user].isVerified = _verified;
        identities[_user].lastUpdated = block.timestamp;
        
        // Update reputation score based on verification status
        if (_verified) {
            _updateReputationScore(_user, 100);
        } else {
            _updateReputationScore(_user, -50);
        }
        
        emit IdentityUpdated(_user, block.timestamp);
    }
    
    // Additional utility functions
    
    /**
     * @dev Update user's profile information
     * @param _name New name
     * @param _email New email
     * @param _profileHash New profile hash
     */
    function updateProfile(
        string memory _name,
        string memory _email,
        string memory _profileHash
    ) public identityExists(msg.sender) {
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_email).length > 0, "Email cannot be empty");
        
        identities[msg.sender].name = _name;
        identities[msg.sender].email = _email;
        identities[msg.sender].profileHash = _profileHash;
        identities[msg.sender].lastUpdated = block.timestamp;
        
        emit IdentityUpdated(msg.sender, block.timestamp);
    }
    
    /**
     * @dev Revoke a credential
     * @param _user The user whose credential to revoke
     * @param _credentialIndex The index of the credential to revoke
     */
    function revokeCredential(address _user, uint256 _credentialIndex) public onlyTrustedIssuer {
        require(_credentialIndex < userCredentials[_user].length, "Invalid credential index");
        
        userCredentials[_user][_credentialIndex].isValid = false;
        
        // Decrease reputation score for revoked credential
        _updateReputationScore(_user, -30);
        
        emit CredentialRevoked(_user, _credentialIndex, block.timestamp);
    }
    
    /**
     * @dev Add a trusted issuer
     * @param _issuer The address to add as a trusted issuer
     */
    function addTrustedIssuer(address _issuer) public onlyOwner {
        trustedIssuers[_issuer] = true;
        emit TrustedIssuerAdded(_issuer, block.timestamp);
    }
    
    /**
     * @dev Remove a trusted issuer
     * @param _issuer The address to remove as a trusted issuer
     */
    function removeTrustedIssuer(address _issuer) public onlyOwner {
        require(_issuer != owner, "Cannot remove owner as trusted issuer");
        trustedIssuers[_issuer] = false;
        emit TrustedIssuerRemoved(_issuer, block.timestamp);
    }
    
    /**
     * @dev Get user's credentials count
     * @param _user The user's address
     * @return The number of credentials
     */
    function getCredentialsCount(address _user) public view returns (uint256) {
        return userCredentials[_user].length;
    }
    
    /**
     * @dev Get a specific credential
     * @param _user The user's address
     * @param _index The credential index
     * @return The credential details
     */
    function getCredential(address _user, uint256 _index) public view returns (Credential memory) {
        require(_index < userCredentials[_user].length, "Invalid credential index");
        return userCredentials[_user][_index];
    }
    
    /**
     * @dev Check if a credential is still valid (not expired and not revoked)
     * @param _user The user's address
     * @param _index The credential index
     * @return True if the credential is valid
     */
    function isCredentialValid(address _user, uint256 _index) public view returns (bool) {
        if (_index >= userCredentials[_user].length) return false;
        
        Credential memory cred = userCredentials[_user][_index];
        
        // Check if credential is not revoked and not expired
        return cred.isValid && (cred.expiresAt == 0 || cred.expiresAt > block.timestamp);
    }
    
    /**
     * @dev Internal function to update reputation score
     * @param _user The user's address
     * @param _change The change in reputation (can be negative)
     */
    function _updateReputationScore(address _user, int256 _change) internal {
        Identity storage identity = identities[_user];
        
        if (_change > 0) {
            uint256 newScore = identity.reputationScore + uint256(_change);
            identity.reputationScore = newScore > MAX_REPUTATION_SCORE ? MAX_REPUTATION_SCORE : newScore;
        } else {
            uint256 decrease = uint256(-_change);
            identity.reputationScore = identity.reputationScore > decrease ? 
                identity.reputationScore - decrease : 0;
        }
        
        emit ReputationUpdated(_user, identity.reputationScore, block.timestamp);
    }
    
    /**
     * @dev Get contract statistics
     * @return Total number of identities created
     */
    function getContractStats() public view returns (uint256) {
        return totalIdentities;
    }
}
