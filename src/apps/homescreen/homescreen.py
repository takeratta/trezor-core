from trezor import ui, loop, res
from trezor.utils import unimport


async def swipe_to_rotate():
    from trezor.ui.swipe import Swipe, degrees

    swipe = await Swipe(absolute=True)
    ui.display.orientation(degrees(swipe))

async def animate_tap():
    time_delay = const(40000)
    draw_delay = const(200000)

    ui.display.text_center(130, 220, 'Tap to unlock', ui.BOLD, ui.GREY, ui.BG)

    sleep = loop.sleep(time_delay)
    icon = res.load(ui.ICON_CLICK)
    for t in ui.pulse(draw_delay):
        fg = ui.blend(ui.GREY, ui.DARK_GREY, t)
        ui.display.icon(45, 202, icon, fg, ui.BG)
        yield sleep

async def dim_screen():
    await loop.sleep(5 * 1000000)
    await ui.backlight_slide(ui.BACKLIGHT_DIM)
    while True:
        await loop.sleep(10000000)


@ui.layout
async def display_homescreen():
    from apps.common import storage

    ui.display.clear()
    if not storage.is_initialized():
        ui.display.text_center(ui.SCREEN // 2, ui.SCREEN - 20, 'Go to trezor.io/start', ui.BOLD, ui.FG, ui.BG)
        image = res.load('apps/homescreen/res/bg.toif')
        ui.display.avatar((ui.SCREEN - 144) // 2, (ui.SCREEN - 144) // 2 - 10, image, ui.WHITE, ui.BLACK)
        await dim_screen()
    else:
        label = storage.get_label() or 'My TREZOR'
        ui.display.text_center(ui.SCREEN // 2, 35, label, ui.BOLD, ui.FG, ui.BG)
        image = storage.get_homescreen()
        if not image:
            image = res.load('apps/homescreen/res/bg.toif')
        ui.display.avatar((ui.SCREEN - 144) // 2, (ui.SCREEN - 144) // 2, image, ui.WHITE, ui.BLACK)
        await animate_tap()




@unimport
async def layout_homescreen():
    while True:
        await loop.wait(swipe_to_rotate(), display_homescreen())
