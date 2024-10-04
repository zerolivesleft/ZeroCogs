import re
from redbot.core import commands
from discord.ext import tasks
from collections import defaultdict

class URLGrabber(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        self.channel_id = None
        self.user_id = None
        self.last_message_id = None
        self.url_check.start()

    def cog_unload(self):
        self.url_check.cancel()

    @commands.command()
    async def seturlchannel(self, ctx, channel_id: int):
        """Set the channel to grab URLs from."""
        self.channel_id = channel_id
        await ctx.send(f"URL grabbing channel set to {channel_id}")

    @commands.command()
    async def seturldm(self, ctx, user_id: int):
        """Set the user to send grabbed URLs to."""
        self.user_id = user_id
        await ctx.send(f"URL recipient set to user with ID {user_id}")

    @tasks.loop(minutes=5.0)
    async def url_check(self):
        if not self.channel_id or not self.user_id:
            return

        channel = self.bot.get_channel(self.channel_id)
        user = self.bot.get_user(self.user_id)

        if not channel or not user:
            return

        url_dict = defaultdict(list)
        
        # If we have a last_message_id, start after that message
        kwargs = {'after': self.last_message_id} if self.last_message_id else {}
        
        async for message in channel.history(limit=None, oldest_first=True, **kwargs):
            urls = self.url_pattern.findall(message.content)
            if urls:
                for url in urls:
                    url_dict[message.author.name].append(url)
            self.last_message_id = message.id

        if url_dict:
            dm_content = "URLs found in {}:\n\n".format(channel.name)
            for author, urls in url_dict.items():
                dm_content += f"**{author}**:\n"
                dm_content += "\n".join(urls)
                dm_content += "\n\n"

            # Split the message if it's too long
            while len(dm_content) > 2000:
                split_index = dm_content.rfind('\n', 0, 2000)
                await user.send(dm_content[:split_index])
                dm_content = dm_content[split_index:].lstrip()

            if dm_content:
                await user.send(dm_content)

    @url_check.before_loop
    async def before_url_check(self):
        await self.bot.wait_until_ready()

async def setup(bot):
    await bot.add_cog(URLGrabber(bot))