from .PlaylistCreator import PlaylistCreator

async def setup(bot):
    await bot.add_cog(PlaylistCreator(bot))