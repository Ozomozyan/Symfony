// src/Controller/HelloWorldController.php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HelloWorldController
{
    /**
     * @Route("/", name="hello_world")
     */
    public function index(): Response
    {
        // You can use a template here if you prefer.
        return new Response('<h2>Hello World !</h2>'); #comm
    }
}
