from .PlaylistCreator import PlaylistCreator

async def setup(bot):
    cog = PlaylistCreator(bot)
    await bot.add_cog(cog)
    if hasattr(bot, "tree"):
        try:
            bot.tree.remove_command("playlist")
        except:
            pass
        bot.tree.add_command(cog.playlist)

async def teardown(bot):
    if hasattr(bot, "tree"):
        bot.tree.remove_command("playlist")