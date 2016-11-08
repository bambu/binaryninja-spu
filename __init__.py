from __future__ import absolute_import

from binaryninja import Architecture, BinaryViewType, BigEndian

from .spu import Spu, EM_SPU, DefaultCallingConvention

__version__ = '0.0.1'

Spu.register()
arch = Architecture['spu']
arch.register_calling_convention(DefaultCallingConvention(arch))

BinaryViewType['ELF'].register_arch(EM_SPU, BigEndian, arch)
