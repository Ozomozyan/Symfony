// src/Controller/HelloWorldController.php commit

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
        return new Response('<h2>Hello World from Symfony 7.0.4!</h2>'); #commit
    }
}
