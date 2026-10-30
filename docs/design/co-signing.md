# Co-signing and limits

A ring bounds what moves with three mechanisms: co-signer approval in the ring program, outflow limits in the policy proof, and window limits in Ring RPC. [Spec](../spec.md)

## Who must co-sign

- An operation demands each of its classes that some co-signer account covers.
- The transfers class covers every transfer, delegate move and merge. The deposits class covers a deposit and a transfer with a deposit leg. The withdrawals class covers a transfer with a withdrawal leg.
- A withdrawal exemption proof waives the withdrawals class when each withdrawn asset's gross amount is at or below the asset's withdrawal threshold.
- One co-signer whose scope covers every demanded class signs. A transfer that only crosses a co-sign bound takes any co-signer. With no co-signer account, that transfer fails.
- The co-signer differs from every owner signer, the in-proof owner, the hidden owner and the delegate.

## Outflow limits, in the policy proof

- An asset's outflow is its live outputs, exits included and change to the sender excluded, minus the signed public net of the transfer.
- A deposit counts positive in the net and a withdrawal negative, so a withdrawal adds to the outflow.
- The outflow stays at or below the asset's cap. A zero cap or co-sign bound turns that check off.
- An outflow above the asset's co-sign bound sets the approval bit, and the program then demands a co-signer.

## Window limits, in Ring RPC

- Each asset's record holds a sender cap, a volume cap, a deposit cap and a withdrawal cap, each with its own window in slots. A zero cap is no cap.
- The sender cap counts what one sender transfers and withdraws. The volume cap counts what the ring transfers, deposits and withdraws.
- Ring RPC checks them when it decides whether to co-sign, and the program checks only the co-signature.
- Ring RPC reserves flows at signing and fails closed, see [Flow 9](../spec.md#9-co-signer-limits-configuration). Its store serializes admission, so no allowance is granted twice.

## What passes them

- Window limits apply only to operations that demand a co-signer and that Ring RPC co-signs.
- The limits bind every operation of a class, such as transfers, only when Ring RPC is the one co-signer that covers that class.
- With no co-signer for its classes, a transfer below the co-sign bound never counts.
- A co-signer key outside Ring RPC whose scope covers the demanded classes signs with no window limit.
- Each signing key is its own sender, so one person with many keys passes a sender cap once per key.
- Outflow limits and amount guards sum one transfer. A payment split across transfers passes each part.
- A deposit leg inside a transfer lowers that transfer's outflow.
- The delegate rail runs no outflow check.

## Real-world controls

- A cap per transfer and asset holds.
- Dual control above an amount holds on owner transfers, and the transfer publishes the approval bit. A delegate move sets no approval bit.
- A cap per customer per window holds only on co-signed operations.
- A cap per person across keys does not hold.
