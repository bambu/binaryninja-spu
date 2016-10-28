from __future__ import absolute_import

from binaryninja import Architecture, BinaryViewType, BigEndian

from .spu import SPU, EM_SPU

__version__ = '0.0.1'

SPU.register()
arch = Architecture['spu']
BinaryViewType['ELF'].register_arch(EM_SPU, BigEndian, arch)
