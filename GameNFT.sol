// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract GameNFT is ERC721, ERC721Enumerable, Ownable, AccessControl {
    string public PROVENANCE="Ethereum";
    address public MASTER;
    bytes32 public constant MASTER_ROLE = keccak256('MASTER_ROLE');
    bytes32 public constant ADMIN_ROLE = keccak256('ADMIN_ROLE');
  
    bool public saleIsActive = true;
    string private _baseURIextended;
     // Mapping from token ID to auth id
    mapping(uint256 => uint256) public _tokenAuths;
    // Mapping from sign to use
    mapping(uint256 => bool) authIdUsed;

    constructor(string memory _name, string memory _symbol, string memory baseuri, address masterAddress, address[] memory admins) ERC721(_name, _symbol) {
        MASTER = masterAddress;
        _baseURIextended = baseuri;
        _setupRole(MASTER_ROLE, MASTER);
        _setupRole(ADMIN_ROLE, MASTER);
        _setRoleAdmin(ADMIN_ROLE, MASTER_ROLE);
        for(uint i = 0; i < admins.length; i ++){
            grantRole(ADMIN_ROLE, admins[i]);
        }
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize) internal override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, ERC721Enumerable,AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function setBaseURI(string memory baseURI_) external onlyRole(ADMIN_ROLE) {
        _baseURIextended = baseURI_;
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseURIextended;
    }

    function setProvenance(string memory provenance) public onlyRole(MASTER_ROLE) {
        PROVENANCE = provenance;
    }

    function setSaleState(bool newState) public onlyRole(ADMIN_ROLE) {
        saleIsActive = newState;
    }

    function mintSerials(uint256 startauthid, uint256 num) public onlyRole(ADMIN_ROLE) {
        for(uint i = 0; i < num; i ++){
            mint(MASTER, startauthid + i);
        }
    }

    function mint(address to, uint256 authId) internal {
         uint256 tokenId = totalSupply() + 1;
        _safeMint(to, tokenId);
        _tokenAuths[tokenId] = authId;
        authIdUsed[authId] = true;
    }

    function buy(address to, uint256[] memory authIds, uint256 totalprice, uint256 deadline, IERC20 token, bytes memory _signature) public{
        require(saleIsActive, "Sale must be active to mint tokens");
        require(totalprice >= 0, "Price must not less than zero");
        require(token.balanceOf(_msgSender()) >= totalprice, "Insufficient price");
        require(verify(to, authIds, totalprice, deadline, abi.encodePacked(address(token)), _signature), "invalid signature ");
        require(deadline <= 0 || deadline >= block.timestamp, "Signature has expired");
        for(uint i = 0; i < authIds.length; i ++){
            require(!authIdUsed[authIds[i]], "Authid used");
        }
        if (totalprice > 0){
            token.transferFrom(_msgSender(), address(this), totalprice);
        }
        for(uint i = 0; i < authIds.length; i ++){
            mint(to, authIds[i]);  
        }
    }

    function withdraw() public onlyRole(ADMIN_ROLE) {
        uint balance = address(this).balance;
        payable(MASTER).transfer(balance);
    }

     function withdrawToken(uint256 _amount, IERC20 token) public onlyRole(ADMIN_ROLE) {
        token.transfer(MASTER, _amount);
    }

    function isAdmin(address user) public view returns(bool) {
        return hasRole(ADMIN_ROLE, user);
    }

    function getAuthId(uint256 tokenId) public view returns(uint256) {
        return _tokenAuths[tokenId];
    }

    function getAuthIds(uint256[] memory tokenIds) public view returns(uint256[] memory) {
        uint256[] memory authids = new uint256[](tokenIds.length);
        for(uint i = 0; i < tokenIds.length; i ++){
            authids[i] = getAuthId(tokenIds[i]);
        }
        return authids;
    }

    function authHasUsed(uint256 authid) public view returns(bool){
        return authIdUsed[authid];
    }

    function getAllNfts(address user) public view returns(uint256[] memory) {
        uint256 length = ERC721.balanceOf(user);
        uint256[] memory tokenIds = new uint256[](length);
        for(uint256 i = 0; i < length; i++) {
            tokenIds[i] = (tokenOfOwnerByIndex(user,i));
        }
        return tokenIds;
    } 

    function getMessageHash(address _to, uint256[] memory authIds, uint256 price,uint256 deadline, bytes memory token) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(authIds, _to, price, deadline, token));
    }

    function verify(address _to, uint256[] memory authIds, uint256 price, uint256 deadline, bytes memory token, bytes memory signature) internal view returns (bool) {
        bytes32 messageHash = getMessageHash(_to, authIds, price, deadline, token);
        return hasRole(ADMIN_ROLE, recoverSigner(getEthSignedMessageHash(messageHash), signature));
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        internal
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
    

    function getEthSignedMessageHash(bytes32 _messageHash)
        internal view
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19", PROVENANCE, " Signed Message:\n32", _messageHash)
            );
    }
}