package structs

import (
	"encoding/json"
	uagc "github.com/drlzh/mng-app-user-auth-prot/user_auth_global_config"
)

type AuthorityIntent struct {
	Intent string `json:"intent"`
}

type AuthorityNode struct {
	NodeID                     string            `json:"node_id"` // could be randomly generated
	AuthorityUser              uagc.UniqueUser   `json:"authority_user"`
	AuthorityIntentCount       int               `json:"authority_intent_count"`
	AuthorityIntents           []AuthorityIntent `json:"authority_intents"`
	AuthorizingAtUnixTimestamp int64             `json:"authorizing_at_unix_timestamp"`
	Nonce                      string            `json:"nonce"`
	AuthoritySignatureKeyID    string            `json:"authority_signature_key_id"`
	AuthoritySignature         string            `json:"authority_signature"`
}

type AuthorityLinkedListNode struct {
	PreviousAuthorityNodeID   string        `json:"previous_authority_node_id,omitempty"`
	ThisAuthorityNode         AuthorityNode `json:"this_authority_node"`
	IsTrustAnchor             bool          `json:"is_trust_anchor"`
	IsIntermediateAuthority   bool          `json:"is_intermediate_authority"`
	IsLastAuthority           bool          `json:"is_last_authority"`
	NextAuthorityNodeID       string        `json:"next_authority_node_id,omitempty"`
	AdditionalAuthorityNodeID string        `json:"additional_authority_node_id,omitempty"`
}

type ActorContext struct {
	AuthorityNodeCount int                       `json:"authority_node_count,omitempty"` // How many authoritative users are involved
	AuthorityChain     []AuthorityLinkedListNode `json:"authority_chain,omitempty"`      //
	TargetUserCount    int                       `json:"target_user_count"`              // How many?
	TargetUsers        []uagc.UniqueUser         `json:"target_users"`                   // target user(s), e.g., child or reset target
	InitiatingUser     uagc.UniqueUser           `json:"initiating_user"`                // who initiated it (e.g., parent, staff)
	Payload            json.RawMessage           `json:"payload"`                        // Reserved
}

// Authority Chain example cases:
// "Who has the right to authorize action X, in situation Y, on subject Z - and how that right can be traced and challenged?"
//
// [a]. Manager (Amanda) asks Coach (Dima) for permission to send new user registration magic link,
// which encodes Registration AuthGrant to the new student. If Dima agrees, the AuthorityChain
// becomes: Amanda (Requestor) -> Dima (ProvisioningAuthority) -> Amanda (Issue NewUser AuthGrant)
//
// [b]. A student forgot their password, and ask Amanda for help. If Dima has previously assigned
// Amanda the permission to initiate password resets on his behalf, the AuthorityChain
// becomes: Dima (Authorizes Entitlements::Issurances::Grants::PasswordReset to Amanda) -> Amanda (Issuer of the PasswordReset AuthGrant)
//
// [c]. You assign Dima as a Coach, Dima then assigns Amanda as a Staff, Amanda Registers a new account with Grant issued by Dima
// Artem (Developer, top-level ProvisioningAuthority = TrustAnchor) -> Dima (CoachAuthority/AuthorizingTarget)
// Amanda is not an Authority yet, but an EndUser, as she has not registered an account when this Grant is issued
//
// [d]. Suppose that Amanda has been assigned as a Staff, but Staff does not include the right to
// issue PasswordReset AuthGrant as of now. A student send a request to Amanda to reset password,
// Amanda now has to turn to Dima for approval, and if Dima approves, the full AuthorityChain
// will look like:
// Artem  (TrustAnchor/ProvisioningAuthority)     -> Dima   (CoachAuthority/AuthorizingTarget)   // Role View, now Dima is a Coach
// Dima   (CoachAuthority/ProvisioningAuthority)  -> Amanda (StaffAuthority/AuthorizingTarget)   // Now Amanda is a Staff
// Amanda (StaffAuthority/Requestor)              -> Dima   (UpstreamAuthority/RequestingTarget) // Requestor View
// Dima   (CoachAuthority/ProvisioningAuthority)  -> Amanda (StaffAuthority/AuthorizingTarget)   // Provider View
// Amanda (StaffAuthority/...) (<- Dima <- Artem) -> (nil)                                       // End user is not an Authority
//
// [e]. Today is Belt Exam Day. Dima, in addition to Amanda's existing role-based Staff entitlements, allows Amanda to
// access the <<Student Belt Rank Info>> UI element temporarily (not written into default Staff config).
// Student X want to attend the next Belt Exam and notifies Amanda, Amanda then wishes to update
// student X's Belt Rank from 10 to 9, but that would require Dima's approval
// based on X's Exam performance. If Dima approves, the full AuthorityChain would look like:
// Artem -> Dima -> Amanda (for assigning Dev -> Coach -> Staff role)
// Dima   (CoachAuthority/ProvisioningAuthority)                           -> Amanda (StaffAuthority/AuthorizingTarget) // For BeltRankInfo UI Access Entitlement
// (nil / Student X)                                                       -> Amanda (UpstreamAuthority) // X makes the request for Belt upgrade
// Amanda (StaffAuthority/Requestor)                                       -> Dima (UpstreamAuthority/RequestingTarget) // Request to update X's Belt Rank from 10 to 9
// Upon confirming X's satisfactory Exam performance, the following are added to the Chain:
// Dima   (CoachAuthority/ProvisioningAuthority)                           -> Amanda (StaffAuthority/AuthorizingTarget) // Allows Amanda to modify X's record
// Amanda (StaffAuthority/...) (Dima <=> Amanda bidirectional negotiation) -> (nil / Student X)
//
// A ProvisioningAuthority is considered an enabler. If an action does not require approval/enablement, PA is not relevant.
//
// [f]. Suppose Dima can invite another Coach by default, but adding new coaches would involve Authority role changes,
// which is a sensitive action that you will be notified of (AdvisoryAuthority). The AuthChain would look like:
// Dima (CoachAuthority [Not PA: New Coach is not in the system, cannot be acted on]) -> (nil / New Coach) ->
// -> Dima (CoachAuthority [Not PA: notify only = no enablement; CA carry-over = allowed by virtue of role default])  ->
// -> Artem (TrustAnchor/AdvisoryAuthority [Not PA: Dima already authorized by default]) ->
// -> Dima (PA: Create New Coach Registration AuthGrant) -> (nil / New Coach)
//
// TrustAnchor will be present in all AuthChains.
//
// A more complex scenario will involve two TAs, such as:
// [g]. Zhenhai put Dima in a hidden beta test for a new Coach Assignment UI, Dima operates on that UI:
// Zhenhai (TA/PA) -> Dima (CA/AT) -> Dima (CA) -> (nil) -> Dima (CA) -> Zhenhai + Artem (TA/AA) -> Dima (CA/PA) -> (nil)
//
// Developers / TrustAnchors will NOT have hierarchies inbuilt.
// Doing so will violate the decentralized and distributed nature of the auth service and
// the authority structure it is modeled after, the former being its one single core goal.
// This means we need to both agree on something before assigning top-level Grants.
// But, given that in a production environment, it will most likely
// be you exercising the power in most cases,
// this would be a non-issue :P
//
// AuthChain will only be enabled for sensitive actions, and NOT routine ones.
//
// I also plan to add Byzantine FT-inspired TrustAnchor majority voting in the future, where each existing TA has the ability to add new TAs,
// and no one can stop them, but they will all be notified.
// If more than 50% (quorum) of existing TAs veto a certain existing TA, that TA will be invalidated for this session, and
// all PAs granted by that TA will be ignored.
// The TA invitation will be tracked just like the existing chain.
// This may be able to facilitate decentralized, 'trustless trust,' where
// corruption will not be allowed even in top echelons and everyone must behave,
// or risk exposing themselves to the public through verifiable, undeniable crypto signatures.
// I think this model is suitable for our dojo,
// which is essentially a miniature-scaled, self-organizing, self-governing, self-sovereign, non-centralizing localized autocracy

//
// I think small establishments like our dojo may actually need more complex and 'unforgiving' tools than what a larger firm may need,
// because we cannot afford any mistakes in a liability-heavy world.
// Think student accusing us of negligence would come out as:
// silence or passive aggression, but still come back = best case
// loss of a student (silently or with drama) = also highly possible
// annoyances, if facing mistrustful/angry/vocal students/parents as we have no buffer, no insurance, no PR = worst case
// We are a Russian-founded dojo in China = lack of local institutional support
//
// Examples:
// Q1: Why did your staff member change my login password/profile without telling me? (delegated auth)
// A1: We’re sorry, our staff had admin access and may have made that change...
// A+: This change was initiated by Amanda on Aug 1, 12:00, but she was acting with your signed authorization, issued via your phone on July 31, 13:30.
//
// Q2: Why can staff see my/my child’s private profile, without my approval? (time-windowed auth)
// A3: Staff have access to most student profiles. We assume they act professionally and don’t misuse it...
// A+: Profile data was visible to Amanda on July 30 only because Dima granted her temporary access for exam coordination. That grant expired after 6h.
//
// Q3: Zhenhai (TA) seems to have overridden his own Belt Rank from 10 to 1 without anyone's consent? (TA anti-corruption)
// A4: Well, since Zhenhai enjoys comparing himself to dictators, I guess that is quite natural...
// A+: I saw on AuthChain that Zhenhai (TA/PA) -> Zhenhai (nil / Student), where it should be:
//     Artem (TA/PA) -> Dima (CA/AT) [Entitlements::AssignBeltRank]
//     Zhenhai (TA/Requestor) -> Dima (CA/RT) -> (Artem (TA/AA) + Amanda (SA/AA) [implicitly Amanda (SA/AA) <- Dima (CA/PA) <- Artem (TA/PA)] + Zhenhai (TA/AA)) -> Dima (CA/PA) -> nil / Zhenhai (TA/AT)
//     In view of this, we are planning to issue a Veto based on Majority Voting of (Artem (TA/AA) + Dima (CA/AA)) = 2 > Zhenhai (TA/AA) = 1 => Action Invalidated
//
// It is the intention of this new auth scheme to enforce trust and shield the dojo from many kinds of liabilities, which and for the dojo is quite fragile to.
// Coupled with the engagement features offered by the app, I think we can protect the dojo by maintaining its sustainability, through both driving revenue and absorbing shocks.

//
// "Let every domain-level actor rule their world absolutely, as long as it’s provably scoped, consensually granted, and totally revocable by those who backstopped their legitimacy."
//    -- I said that. (Are you expecting a philosopher's name here?) XXD
