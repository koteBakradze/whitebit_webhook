from decimal import Decimal
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union



@dataclass
class Confirmations:
    actual: int
    required: int


# ----- code.apply -------------------------------------------------------------
@dataclass
class CodeApplyParams:
    code: str
    nonce: int


# ----- deposit.* --------------------------------------------------------------
@dataclass
class DepositParams:
    address: str
    amount: Decimal
    createdAt: int
    currency: str
    description: Optional[str]
    fee: Decimal
    memo: Optional[str]
    method: int  # 1 = deposit
    network: Optional[str]
    status: int  # docs list "Pending - 15"
    ticker: str
    transactionHash: Optional[str]
    uniqueId: Optional[str]
    confirmations: Optional[Confirmations] = None


# ----- withdraw.* -------------------------------------------------------------
@dataclass
class WithdrawParams:
    address: str
    amount: Decimal
    createdAt: int
    currency: str
    ticker: str
    description: Optional[str]
    fee: Decimal
    memo: Optional[str]
    method: int  # 2 = withdraw
    network: Optional[str]
    status: int
    transactionHash: Optional[str]
    uniqueId: Optional[str]


# Envelope that wraps every webhook
@dataclass
class WebhookEnvelope:
    method: str
    params: Union[CodeApplyParams, DepositParams, WithdrawParams, Dict[str, Any]]
    id: str

