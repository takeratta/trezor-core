# Automatically generated by pb2py
import protobuf as p
from .NEMAggregateModification import NEMAggregateModification
from .NEMImportanceTransfer import NEMImportanceTransfer
from .NEMMosaicCreation import NEMMosaicCreation
from .NEMMosaicSupplyChange import NEMMosaicSupplyChange
from .NEMProvisionNamespace import NEMProvisionNamespace
from .NEMTransactionCommon import NEMTransactionCommon
from .NEMTransfer import NEMTransfer


class NEMSignTx(p.MessageType):
    FIELDS = {
        1: ('transaction', NEMTransactionCommon, 0),
        2: ('multisig', NEMTransactionCommon, 0),
        3: ('transfer', NEMTransfer, 0),
        4: ('cosigning', p.BoolType, 0),
        5: ('provision_namespace', NEMProvisionNamespace, 0),
        6: ('mosaic_creation', NEMMosaicCreation, 0),
        7: ('supply_change', NEMMosaicSupplyChange, 0),
        8: ('aggregate_modification', NEMAggregateModification, 0),
        9: ('importance_transfer', NEMImportanceTransfer, 0),
    }
    MESSAGE_WIRE_TYPE = 69
