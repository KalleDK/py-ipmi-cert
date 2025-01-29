import asyncio
import dataclasses


@dataclasses.dataclass
class Worker:
    updated_at: float = 0
    wait_time: float = 4.0
    reload_time: float = 3.0
    token: str = ""

    task: asyncio.Task[None] | None = None

    def set_token(self, token: str):
        print("Updating Token", token)
        self.updated_at = asyncio.get_running_loop().time()
        self.token = token

    @property
    def must_reload(self):
        return self.updated_at + self.reload_time < asyncio.get_running_loop().time()

    @property
    def max_delay_to_reload(self):
        return self.updated_at + self.wait_time - asyncio.get_running_loop().time()

    async def reload(self):
        while True:
            if self.must_reload:
                await asyncio.sleep(1)
                self.set_token("new_token")
            print("Waiting", self.max_delay_to_reload)
            await asyncio.sleep(self.max_delay_to_reload)

    def start(self):
        self.task = asyncio.create_task(self.reload())


async def main():
    worker = Worker()

    worker.start()
    pre = asyncio.get_running_loop().time()
    print("Sleeping")
    for i in range(3):
        await asyncio.sleep(2)
        print("Slept", i)
        worker.set_token("outside")
    await asyncio.sleep(6)
    print("Elapsed", asyncio.get_running_loop().time() - pre)
    if worker.task is not None:
        worker.task.cancel()
    print("Elapsed", asyncio.get_running_loop().time() - pre)
    print("Cancelled task")


asyncio.run(main())
