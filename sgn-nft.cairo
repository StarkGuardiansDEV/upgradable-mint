%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import (
    get_caller_address,
    get_contract_address,
    get_block_timestamp,
)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import (
    assert_not_zero,
    split_felt,
    assert_lt_felt,
    unsigned_div_rem,
)
from starkware.cairo.common.uint256 import Uint256, uint256_le, assert_uint256_le, uint256_add
from starkware.cairo.common.math_cmp import is_le, is_not_zero

from openzeppelin.introspection.erc165.library import ERC165
from openzeppelin.token.ERC20.IERC20 import IERC20
from openzeppelin.token.erc721.library import ERC721

from openzeppelin.access.ownable.library import Ownable
from openzeppelin.security.pausable.library import Pausable
from openzeppelin.security.reentrancyguard.library import ReentrancyGuard
from openzeppelin.upgrades.library import Proxy
from StarknetSocialV2.starknetSocialMetadata import (
    ERC721_Metadata_initializer,
    ERC721_Metadata_tokenURI,
    ERC721_Metadata_setBaseTokenURI,
)
from Libraries.DolvenMerkleVerifier import DolvenMerkleVerifier
from openzeppelin.token.erc721.enumerable.library import ERC721Enumerable

//id => 0 == public
struct RoundDetails {
    isInitialized : felt,
    startTime : felt,
    endTime : felt,
    price : felt,
}

struct UserData {
    user_mint_count : felt,
    user_total_payment : felt,
}

@storage_var
func supply_limit() -> (res: felt) {
}

@storage_var
func merkle_root(root_id : felt) -> (res: felt) {
}

@storage_var
func payment_method() -> (index: felt) {
}

@storage_var
func mint_limit_for_team() -> (limit: felt) {
}

@storage_var
func round_details(id : felt) -> (details: RoundDetails) {
}

@storage_var
func fee_target() -> (addr: felt) {
}

@storage_var
func user_mint_data(user_address: felt) -> (res: UserData) {
}

@storage_var
func role_mint_limits(role_id : felt) -> (count: felt) {
}

@storage_var
func role_eligible_for_round(round_id: felt, role_id : felt) -> (is_eligible: felt) {
}

@storage_var
func is_refund_available() -> (is_available: felt) {
}

//true ise transfer edilebilir


@external
func initializer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    name: felt, symbol : felt, _supply_limit : felt, manager : felt, _payment_method : felt, _mint_limit_for_team : felt, fee_address : felt) {
    
    let (_manager) = Ownable.owner();
    with_attr error_message("starknetSocial:: woot! already initilaized"){
        assert _manager = 0;
    }

    Ownable.initializer(manager);
    ERC721.initializer(name, symbol);
    ERC721Enumerable.initializer();
    ERC721_Metadata_initializer();
    payment_method.write(_payment_method);
    supply_limit.write(_supply_limit);
    mint_limit_for_team.write(_mint_limit_for_team);
    fee_target.write(fee_address);
    return();
}

// viewers

//ERC-721 Standart
@view
func totalSupply{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}() -> (
    totalSupply: Uint256
) {
    let (totalSupply: Uint256) = ERC721Enumerable.total_supply();
    return (totalSupply,);
}

@view
func tokenByIndex{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    index: Uint256
) -> (tokenId: Uint256) {
    let (tokenId: Uint256) = ERC721Enumerable.token_by_index(index);
    return (tokenId,);
}

@view
func tokenOfOwnerByIndex{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    owner: felt, index: Uint256
) -> (tokenId: Uint256) {
    let (tokenId: Uint256) = ERC721Enumerable.token_of_owner_by_index(owner, index);
    return (tokenId,);
}

@view
func supportsInterface{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    interfaceId: felt
) -> (success: felt) {
    let (success) = ERC165.supports_interface(interfaceId);
    return (success,);
}

@view
func name{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (name: felt) {
    let (name) = ERC721.name();
    return (name,);
}

@view
func return_payment_method{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (method: felt) {
    let (method) = payment_method.read();
    return (method,);
}

@view
func symbol{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (symbol: felt) {
    let (symbol) = ERC721.symbol();
    return (symbol,);
}

@view
func balanceOf{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(owner: felt) -> (
    balance: Uint256
) {
    let (balance: Uint256) = ERC721.balance_of(owner);
    return (balance,);
}

@view
func ownerOf{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(tokenId: Uint256) -> (
    owner: felt
) {
    let (owner: felt) = ERC721.owner_of(tokenId);
    return (owner,);
}

@view
func getApproved{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    tokenId: Uint256
) -> (approved: felt) {
    let (approved: felt) = ERC721.get_approved(tokenId);
    return (approved,);
}

@view
func isApprovedForAll{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    owner: felt, operator: felt
) -> (isApproved: felt) {
    let (isApproved: felt) = ERC721.is_approved_for_all(owner, operator);
    return (isApproved,);
}


@view
func tokenURI{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    token_id: Uint256
) -> (token_uri_len: felt, token_uri: felt*) {
    let (token_uri_len, token_uri) = ERC721_Metadata_tokenURI(token_id);
    return (token_uri_len=token_uri_len, token_uri=token_uri);
}


@view
func owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (owner: felt) {
    let (owner: felt) = Ownable.owner();
    return (owner,);
}


@external
func approve{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    to: felt, tokenId: Uint256
) {
    ERC721.approve(to, tokenId);
    return ();
}

@external
func setApprovalForAll{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    operator: felt, approved: felt
) {
    ERC721.set_approval_for_all(operator, approved);
    return ();
}


@external
func transferFrom{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    from_: felt, to: felt, tokenId: Uint256
) {
    ERC721Enumerable.transfer_from(from_, to, tokenId);
    return ();
}

@external
func safeTransferFrom{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    from_: felt, to: felt, tokenId: Uint256, data_len: felt, data: felt*
) {
    ERC721Enumerable.safe_transfer_from(from_, to, tokenId, data_len, data);
    return ();
}

// ERC721 Standart Ends

//Spesific Views Start

@view
func returnAllTokensOfUser{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    user_address : felt
) -> (tokens_len : felt, tokens : felt*) {
    alloc_locals;
    let (user_balance : Uint256) = balanceOf(user_address);
    let balance_as_felt : felt = uint256_to_felt(user_balance);
    let (tokens_len : felt, tokens : felt*) = recursive_tokens(user_address, 0, balance_as_felt);
    return(tokens_len, tokens - tokens_len);
}


@view
func return_role_eligibility{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
role_id : felt, round_id) -> (res : felt) {
    let (res) = role_eligible_for_round.read(round_id, role_id);
    return(res,);
}

@view
func return_role_mint_limit{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
role_id : felt) -> (res : felt) {
    let (res) = role_mint_limits.read(role_id);
    return(res,);
}

@view
func return_round_info{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
round_id : felt) -> (res : RoundDetails) {
    let (res) = round_details.read(round_id);
    return(res,);
}

@view
func return_root{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(id : felt) -> (res : felt) {
    let (res) = merkle_root.read(id);
    return(res,);
}

@view
func return_supply_limit{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt) {
    let (res) = supply_limit.read();
    return(res,);
}

@view
func isWhitelisted{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    user_address : felt, user_class : felt, user_proof_len: felt,  user_proof : felt*, merkle_root_id : felt
) -> (res : felt, leaf : felt) {
    alloc_locals;
    let _merkle_root : felt = merkle_root.read(merkle_root_id);
    let is_diff_than_zero : felt = is_not_zero(_merkle_root);
    with_attr error_message("launchpad::isWhitelisted merkle_root cannot be zero"){
        assert is_diff_than_zero = TRUE;
    }
    let (leaf) = hash_user_data(user_address, user_class);
    let isVerified : felt = DolvenMerkleVerifier.verify(leaf, _merkle_root, user_proof_len, user_proof);
    return (isVerified, leaf);
}


@view
func return_user_mint_count{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(user_address : felt ) -> (res: felt) {
    let (mint_data) = user_mint_data.read(user_address);
    return (mint_data.user_mint_count,);
}


@view
func return_user_data{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(user_address : felt ) -> (res: UserData) {
    let (mint_data) = user_mint_data.read(user_address);
    return (mint_data,);
}

@view
func _isPaused{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    let (status) = Pausable.is_paused();
    return (status,);
}

@view
func return_is_refund_available{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    let (status) = is_refund_available.read();
    return (status,);
}

//Spesific Views End

//Spesific Externals Starts

@external
func mintForTeam{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    mint_amount : felt, 
) {
    Ownable.assert_only_owner();
    let _mint_limit : felt = mint_limit_for_team.read(); 
    with_attr error_message("Launchpad::mintForTeam: cannot mint more than limit"){
        assert_lt_felt(mint_amount, _mint_limit);
    }
    let (msg_sender) = get_caller_address();
    recursive_mint(mint_amount, 0, msg_sender);
    return();
}

@external
func setRecursivelyMerkleRoot{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    roots_len : felt, roots : felt*,  ids_len : felt, ids: felt*
) {
    Ownable.assert_only_owner();
    
    recursive_merkle_root(ids, ids_len, roots, roots_len, 0);
    return();
}

@external
func switchContract{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.assert_only_owner();
    let _isContractPaused : felt = _isPaused();
    if(_isContractPaused == TRUE){
        Pausable._pause();
        return();
    }else{
        Pausable._unpause();
        return();
    }
}

@external
func setRounds{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    id:felt, _startTime : felt, _endTime: felt, _price : felt, _isActive : felt
) {
    Ownable.assert_only_owner();
    
    let round : RoundDetails = RoundDetails(
        isInitialized=_isActive,
        startTime=_startTime,
        endTime=_endTime,
        price=_price,
    );
    round_details.write(id, round);
    return();
}


@external
func refund{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    Pausable.assert_not_paused();
    ReentrancyGuard.start();

    let (msg_sender) = get_caller_address();
    let (this) = get_contract_address();

    let _is_refund_available : felt = is_refund_available.read();
    with_attr error_message("launchpad::time_check: too early"){
        assert _is_refund_available = TRUE;
    } 
    let _user_mint_data : UserData = user_mint_data.read(msg_sender);
    let is_not_payment_made : felt = is_le(_user_mint_data.user_total_payment, 0);

    with_attr error_message("launchpad::refund payment is not done"){
        assert is_not_payment_made = FALSE;
    }

    let (tokens_len, tokens) = returnAllTokensOfUser(msg_sender);
    recursive_burn(tokens_len, 0 , tokens);

    let _cost_as_uint : Uint256 = felt_to_uint256(_user_mint_data.user_total_payment);
    let _payment_method : felt = payment_method.read();
    let (success : felt) = IERC20.transfer(_payment_method, msg_sender, _cost_as_uint);
    with_attr error_message("StarkGuardians::payment failed ") {
        assert success = TRUE;
    }
    let _new_user_data : UserData = UserData(0, 0);
    user_mint_data.write(msg_sender, _new_user_data);
    
    
    ReentrancyGuard.end();
    return();
}


@external
func mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(round_id : felt, user_role : felt, mint_amount : felt, proof_len : felt, proof :felt*, merkle_root_id : felt) {
    alloc_locals;
    ReentrancyGuard.start();
    Pausable.assert_not_paused();
    let (caller_address) = get_caller_address();
    
    assert_not_zero(mint_amount);
    soldout_check(mint_amount);

    let (round_info) = return_round_info(round_id);
    let mint_limit : felt = role_mint_limits.read(user_role);

    round_activity_check(round_info.isInitialized);
    time_check(round_info.startTime, round_info.endTime);
    //user mint per wallet limit check 
    mint_limit_check(caller_address, mint_limit, mint_amount);

    if(round_id == 0){
    //public round
        transfer_fee(caller_address, round_info.price, mint_amount);
        update_user(caller_address, mint_amount, round_info.price);
        recursive_mint(mint_amount, 0, caller_address);
        ReentrancyGuard.end();
        return();
    }else{
        //special round
        check_role_eligible_for_round(user_role, round_id);
        let (is_eligible : felt, leaf : felt) = isWhitelisted(caller_address, user_role, proof_len, proof, merkle_root_id);
        with_attr error_message("launchpad::mint not eligible for round"){
            assert is_eligible = TRUE;
        }
        transfer_fee(caller_address, round_info.price, mint_amount);
        update_user(caller_address, mint_amount, round_info.price);
        recursive_mint(mint_amount, 0, caller_address);
        ReentrancyGuard.end();
        return();
    }
}

func recursive_mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    size : felt, index : felt, to : felt
) {
    let (supply: Uint256) = ERC721Enumerable.total_supply();

    if(size == index){
        return();
    }

    ERC721Enumerable._mint(to, supply);
    return recursive_mint(size, index + 1, to);
}


func recursive_burn{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    size : felt, index : felt, token_ids : felt*
) {
   

    if(size == index){
        return();
    }

    let tokenId : Uint256 = felt_to_uint256(token_ids[index]);
    ERC721.assert_only_token_owner(tokenId);
    ERC721Enumerable._burn(tokenId);
    return recursive_burn(size, index + 1, token_ids);
}


func recursive_merkle_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ids: felt*, ids_len : felt, roots : felt*, roots_len : felt, index: felt
) {
    if(index == ids_len){
        return();
    }
    merkle_root.write(ids[index], roots[index]);
    recursive_merkle_root(ids, ids_len, roots, roots_len, index + 1);
    return();
}

@external
func burn{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(tokenId: Uint256) {
    ERC721.assert_only_token_owner(tokenId);
    ERC721Enumerable._burn(tokenId);
    return ();
}


@external
func setTokenURI{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    base_token_uri_len: felt, base_token_uri: felt*, token_uri_suffix: felt
) {
    Ownable.assert_only_owner();
    ERC721_Metadata_setBaseTokenURI(base_token_uri_len, base_token_uri, token_uri_suffix);
    return ();
}


@external
func transferOwnership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    newOwner: felt
) {
    Ownable.transfer_ownership(newOwner);
    return ();
}

@external
func renounceOwnership{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.renounce_ownership();
    return ();
}


@external
func set_supply_limit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(req : felt) {
    Ownable.assert_only_owner();
    
    supply_limit.write(req);
    return ();
}

@external
func set_payment_method{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(req : felt) {
    Ownable.assert_only_owner();
    
    payment_method.write(req);
    return ();
}


@external
func set_role_mint_limit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(role_id : felt, mint_limit : felt) {
    Ownable.assert_only_owner();
    
    role_mint_limits.write(role_id, mint_limit);
    return ();
}

@external
func upgrade{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_implementation: felt
) {
    // Verify that caller is admin
    Ownable.assert_only_owner();
    Proxy._set_implementation_hash(new_implementation);
    return ();
}

@external
func set_round_eligibility{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(round_id : felt, role_id : felt, is_eligible : felt) {
    Ownable.assert_only_owner();
    role_eligible_for_round.write(round_id, role_id, is_eligible);
    return ();
}

@external
func set_refund_status{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(status : felt) {
    Ownable.assert_only_owner();
    is_refund_available.write(status);
    return ();
}


//Internals

func recursive_tokens{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    user_address : felt, index : felt, loop_size : felt
) -> (tokens_len : felt, tokens : felt*){
    alloc_locals;
   

    if(loop_size == index){
        let (found_tokens: felt*) = alloc();
        return (0, found_tokens,);
    }
    
    let uint_index : Uint256 = felt_to_uint256(index);
    let (userToken : Uint256) = tokenOfOwnerByIndex(user_address, uint_index);
    let felt_token_id : felt = uint256_to_felt(userToken); 

    let (tokens_len, token_location: felt*) = recursive_tokens(user_address, index + 1, loop_size);
    assert [token_location] = felt_token_id;
    return (tokens_len + 1, token_location + 1,);
}

func time_check{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(start_time : felt, end_time : felt){
    let (now) = get_block_timestamp();
    let is_started : felt = is_le(start_time, now);
    let is_ended : felt = is_le(end_time, now);
    with_attr error_message("launchpad::time_check: too early"){
        assert is_started = TRUE;
    } 
    with_attr error_message("launchpad::time_check: too late"){
        assert is_ended = FALSE;
    } 
    return();
}

func update_user{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(user_address : felt, mint_amount : felt, price : felt){
    let _user_minted_data : UserData = user_mint_data.read(user_address);
    let _user_payment : felt = price * mint_amount;
    let _user_total_payment : felt = _user_minted_data.user_total_payment + _user_payment;
    let total : felt = _user_minted_data.user_mint_count + mint_amount;
    let new_user_data : UserData = UserData(total, _user_total_payment); 
    user_mint_data.write(user_address, new_user_data);
    return();
}

func round_activity_check{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(val : felt){
    with_attr error_message("launchpad::round_activity_check: not active"){
        assert val = TRUE;
    } 
    return();
}

func mint_limit_check{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(user_address : felt, max_limit : felt, mint_amount : felt){
    let (now) = get_block_timestamp();
    let _user_minted_data : UserData = user_mint_data.read(user_address);
    
    let total : felt = _user_minted_data.user_mint_count + mint_amount;
    let is_not_exceed : felt = is_le(total, max_limit);
    with_attr error_message("launchpad::mint_limit_check: limit exceeed"){
        assert is_not_exceed = TRUE;
    } 
    return();
}

func check_role_eligible_for_round{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (role_id : felt, round_id : felt){
    let is_eligible : felt = role_eligible_for_round.read(round_id, role_id);
    with_attr error_message("StarkGuardians::check_role_eligible_for_round role is not eligible for round") {
        assert is_eligible = TRUE;
    }
    return ();
}
 
func soldout_check{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(mint_amount : felt){
    alloc_locals;
    let _supply : Uint256 = totalSupply();
    let _supply_limit : felt = supply_limit.read();
    let _supply_limit_as_uint256 : Uint256 = felt_to_uint256(_supply_limit);
    let mint_amount_as_uint : Uint256 = felt_to_uint256(mint_amount);
    let (total_minted_count, _)  = uint256_add(_supply, mint_amount_as_uint);
    with_attr error_message("StarkGuardians::cannot mint more than limited supply") {
        assert_uint256_le(total_minted_count, _supply_limit_as_uint256);
    }
    return();
}


func transfer_fee{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(_from : felt, _price : felt, mint_amount : felt){
    let total_cost : felt = _price * mint_amount;
    let _cost_as_uint : Uint256 = felt_to_uint256(total_cost);
    let _payment_method : felt = payment_method.read();
    let _fee_addr : felt = fee_target.read();
    let (success : felt) = IERC20.transferFrom(_payment_method, _from, _fee_addr, _cost_as_uint);
    with_attr error_message("StarkGuardians::payment failed ") {
        assert success = TRUE;
    }
    return();
}

func hash_user_data{pedersen_ptr : HashBuiltin*}(account : felt, class : felt) -> (
    res : felt
){
    let (res) = hash2{hash_ptr=pedersen_ptr}(account, class);
    return (res=res);
}

func felt_to_uint256{range_check_ptr}(x) -> (uint_x: Uint256) {
    let (high, low) = split_felt(x);
    return (Uint256(low=low, high=high),);
}

func uint256_to_felt{range_check_ptr}(value: Uint256) -> (value: felt) {
    assert_lt_felt(value.high, 2 ** 123);
    return (value.high * (2 ** 128) + value.low,);
}