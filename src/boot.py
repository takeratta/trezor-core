from trezor import config
from trezor.pin import pin_to_int, show_pin_timeout
from trezor import loop
from trezor import ui

from apps.common.request_pin import request_pin


async def unlock_layout():

    while True:
        try:
            if config.has_pin():
                pin = await request_pin('Unlock My TREZOR') # FIXME
            else:
                pin = ''

            if config.unlock(pin_to_int(pin), show_pin_timeout):
                return
            else:
                await unlock_failed()

        except:
            pass

async def unlock_failed():
    pass


config.init()
ui.display.backlight(ui.BACKLIGHT_NONE) # Bootloader ends faded out
loop.schedule(ui.backlight_slide(ui.BACKLIGHT_NORMAL))
loop.schedule(unlock_layout())
loop.run()
