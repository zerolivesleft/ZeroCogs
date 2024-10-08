from .PlaylistCreator import PlaylistCreator

async def setup(bot):
    await bot.add_cog(PlaylistCreator(bot))

async def teardown(bot):
    if hasattr(bot, "tree"):
        bot.tree.remove_command("playlist")