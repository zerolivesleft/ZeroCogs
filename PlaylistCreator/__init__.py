from .PlaylistCreator import PlaylistCreator

async def setup(bot):
    cog = PlaylistCreator(bot)
    await bot.add_cog(cog)
    if hasattr(bot, "tree"):
        bot.tree.add_command(cog.playlist)